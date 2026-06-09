// routes/mobile-shop.js — Shopify product proxy for mobile app

const axios = require('axios');

const SHOPIFY_DOMAIN        = process.env.SHOPIFY_SHOP_DOMAIN;
const SHOPIFY_CLIENT_ID     = process.env.SHOPIFY_MOBILE_CLIENT_ID;
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_MOBILE_CLIENT_SECRET;

let _token = null, _tokenExpiry = 0;

async function getShopifyToken() {
  if (_token && Date.now() < _tokenExpiry - 5 * 60 * 1000) return _token;
  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: SHOPIFY_CLIENT_ID,
    client_secret: SHOPIFY_CLIENT_SECRET,
  });
  const res = await axios.post(
    `https://${SHOPIFY_DOMAIN}/admin/oauth/access_token`,
    params.toString(),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  _token = res.data.access_token;
  _tokenExpiry = Date.now() + (res.data.expires_in || 86399) * 1000;
  console.log('[SHOP] Shopify token refreshed');
  return _token;
}

async function shopifyGet(path) {
  const token = await getShopifyToken();
  const res = await axios.get(`https://${SHOPIFY_DOMAIN}/admin/api/2024-04/${path}`, {
    headers: { 'X-Shopify-Access-Token': token }
  });
  return res.data;
}

module.exports = (app, cache) => {

  // GET /api/app/products — cursor-based pagination
  app.get('/api/app/products', async (req, res) => {
    try {
      const { limit = 50, collection_id, vendor, product_type, page_info } = req.query;

      const token = await getShopifyToken();
      let url;

      if (page_info) {
        // Cursor pagination - page_info overrides all other params
        url = `https://${SHOPIFY_DOMAIN}/admin/api/2024-04/products.json?limit=${limit}&page_info=${page_info}&fields=id,title,handle,variants,images,product_type,vendor,tags`;
      } else if (collection_id) {
        // First page of a collection
        const productIds = await shopifyGet(`collections/${collection_id}/products.json?limit=${limit}&fields=id`);
        const ids = (productIds.products || []).map(p => p.id).join(',');
        if (!ids) return res.json({ success: true, products: [], nextPageInfo: null });
        url = `https://${SHOPIFY_DOMAIN}/admin/api/2024-04/products.json?ids=${ids}&limit=${limit}&fields=id,title,handle,variants,images,product_type,vendor,tags`;
      } else {
        let q = `products.json?limit=${limit}&status=active&fields=id,title,handle,variants,images,product_type,vendor,tags`;
        if (vendor) q += `&vendor=${encodeURIComponent(vendor)}`;
        if (product_type) q += `&product_type=${encodeURIComponent(product_type)}`;
        url = `https://${SHOPIFY_DOMAIN}/admin/api/2024-04/${q}`;
      }

      const result = await axios.get(url, { headers: { 'X-Shopify-Access-Token': token } });
      const data   = result.data;

      // Extract next page cursor from Link header
      let nextPageInfo = null;
      const linkHeader = result.headers?.link || result.headers?.Link || '';
      if (linkHeader) {
        // Find rel=next link and extract page_info
        const parts = linkHeader.split(',');
        for (const part of parts) {
          if (part.includes('rel="next"')) {
            const piMatch = part.match(/page_info=([^&>s"]+)/);
            if (piMatch) { nextPageInfo = decodeURIComponent(piMatch[1]); break; }
          }
        }
      }

      const products = (data.products || []).map(p => ({
        id:        p.id,
        title:     p.title,
        handle:    p.handle,
        type:      p.product_type,
        vendor:    p.vendor,
        tags:      p.tags,
        price:     p.variants?.[0]?.price || '0',
        comparePrice: p.variants?.[0]?.compare_at_price || null,
        image:     p.images?.[0]?.src || null,
        images:    (p.images || []).map(i => i.src),
        inStock:   p.variants?.some(v => v.inventory_quantity > 0 || v.inventory_management === null),
        variantId: p.variants?.[0]?.id,
      }));

      // Get total count (only on first page)
      let total = null;
      if (!page_info && !collection_id) {
        try {
          const countData = await shopifyGet('products/count.json?status=active');
          total = countData.count;
        } catch(_) {}
      }
      res.json({ success: true, products, count: products.length, nextPageInfo, total });
    } catch (err) {
      console.error('[SHOP] products error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to fetch products.' });
    }
  });

  // GET /api/app/collections — fetches both custom + smart collections
  app.get('/api/app/collections', async (req, res) => {
    try {
      const [customData, smartData] = await Promise.all([
        shopifyGet('custom_collections.json?limit=50&fields=id,title,handle,image'),
        shopifyGet('smart_collections.json?limit=50&fields=id,title,handle,image'),
      ]);
      const custom = (customData.custom_collections || []).map(c => ({ id: c.id, title: c.title, handle: c.handle, image: c.image?.src || null }));
      const smart  = (smartData.smart_collections  || []).map(c => ({ id: c.id, title: c.title, handle: c.handle, image: c.image?.src || null }));
      const collections = [...custom, ...smart];
      res.json({ success: true, collections });
    } catch (err) {
      console.error('[SHOP] collections error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to fetch collections.' });
    }
  });

  // GET /api/app/products/:id
  app.get('/api/app/products/:id', async (req, res) => {
    try {
      const data = await shopifyGet(`products/${req.params.id}.json`);
      const p = data.product;
      if (!p) return res.status(404).json({ success: false, message: 'Product not found.' });
      res.json({
        success: true,
        product: {
          id:       p.id,
          title:    p.title,
          handle:   p.handle,
          type:     p.product_type,
          vendor:   p.vendor,
          tags:     p.tags,
          body:     p.body_html?.replace(/<[^>]*>/g, '') || '',
          price:    p.variants?.[0]?.price || '0',
          comparePrice: p.variants?.[0]?.compare_at_price || null,
          images:   (p.images || []).map(i => i.src),
          variants: p.variants?.map(v => ({
            id:      v.id,
            title:   v.title,
            price:   v.price,
            inStock: v.inventory_quantity > 0 || v.inventory_management === null,
          })),
        }
      });
    } catch (err) {
      console.error('[SHOP] product detail error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to fetch product.' });
    }
  });

  // GET /api/app/menu — uses Storefront API
  app.get('/api/app/menu', async (req, res) => {
    try {
      const handle = req.query.handle || 'main-menu';
      const storefrontToken = process.env.SHOPIFY_STOREFRONT_TOKEN;

      const query = `{
        menu(handle: "${handle}") {
          title
          items {
            id title url
            items {
              id title url
              items { id title url }
            }
          }
        }
      }`;

      const result = await axios.post(
        `https://${SHOPIFY_DOMAIN}/api/2024-04/graphql.json`,
        { query },
        { headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Storefront-Access-Token': storefrontToken,
        }}
      );

      const menu = result.data?.data?.menu;
      if (!menu) return res.json({ success: true, items: [] });
      res.json({ success: true, title: menu.title, items: menu.items || [] });
    } catch (err) {
      console.error('[SHOP] menu error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to fetch menu.' });
    }
  });

  // GET /api/app/get-storefront-token (run once to generate)
  app.get('/api/app/get-storefront-token', async (req, res) => {
    try {
      const token = await getShopifyToken();
      const result = await axios.post(
        `https://${SHOPIFY_DOMAIN}/admin/api/2024-04/storefront_access_tokens.json`,
        { storefront_access_token: { title: 'WHP Mobile App' } },
        { headers: { 'X-Shopify-Access-Token': token } }
      );
      res.json(result.data);
    } catch(e) { res.json({ error: e.message }); }
  });

  // POST /api/app/cart/create — uses checkoutCreate for direct checkout URL
  app.post('/api/app/cart/create', async (req, res) => {
    try {
      const { lines } = req.body;
      if (!lines?.length) return res.status(400).json({ success: false, message: 'No items.' });

      const storefrontToken = process.env.SHOPIFY_STOREFRONT_TOKEN;
      const query = `
        mutation checkoutCreate($input: CheckoutCreateInput!) {
          checkoutCreate(input: $input) {
            checkout { id webUrl }
            checkoutUserErrors { code field message }
          }
        }
      `;
      const variables = {
        input: {
          lineItems: lines.map(l => ({
            variantId: `gid://shopify/ProductVariant/${l.variantId}`,
            quantity: l.quantity,
          })),
          customAttributes: [{ key: 'source', value: 'whp-app' }],
        }
      };

      const result = await axios.post(
        `https://${SHOPIFY_DOMAIN}/api/2024-04/graphql.json`,
        { query, variables },
        { headers: { 'Content-Type': 'application/json', 'X-Shopify-Storefront-Access-Token': storefrontToken } }
      );

      const checkout = result.data?.data?.checkoutCreate?.checkout;
      const errors   = result.data?.data?.checkoutCreate?.checkoutUserErrors;
      console.log('[SHOP] checkout result:', JSON.stringify(result.data?.data));

      if (!checkout) {
        return res.status(400).json({ success: false, message: errors?.[0]?.message || 'Checkout creation failed.' });
      }
      res.json({ success: true, checkoutUrl: checkout.webUrl, cartId: checkout.id });
    } catch (err) {
      console.error('[SHOP] cart create error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to create checkout.' });
    }
  });

  // POST /api/app/customer/token
  app.post('/api/app/customer/token', async (req, res) => {
    try {
      const { shopify_customer_id } = req.body;
      if (!shopify_customer_id) return res.status(400).json({ success: false, message: 'shopify_customer_id required.' });

      const customerData = await shopifyGet(`customers/${shopify_customer_id}.json`);
      const customer = customerData.customer;
      if (!customer) return res.status(404).json({ success: false, message: 'Customer not found.' });

      res.json({
        success: true,
        customer: {
          email:      customer.email || '',
          firstName:  customer.first_name || '',
          lastName:   customer.last_name || '',
          phone:      customer.phone || '',
          shopify_id: customer.id,
        }
      });
    } catch (err) {
      console.error('[SHOP] customer token error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to get customer details.' });
    }
  });

}; // ← single closing brace for module.exports
