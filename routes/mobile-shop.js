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

async function shopifyGetWithHeaders(path) {
  const token = await getShopifyToken();
  const res = await axios.get(`https://${SHOPIFY_DOMAIN}/admin/api/2024-04/${path}`, {
    headers: { 'X-Shopify-Access-Token': token }
  });
  return { data: res.data, headers: res.headers };
}

function extractNextCursor(linkHeader) {
  if (!linkHeader) return null;
  try {
    const links = linkHeader.split(',');
    for (const link of links) {
      if (link.includes('rel="next"')) {
        const urlMatch = link.match(/<([^>]+)>/);
        if (urlMatch) {
          const urlObj = new URL(urlMatch[1]);
          return urlObj.searchParams.get('page_info');
        }
      }
    }
  } catch(_) {}
  return null;
}

module.exports = (app, cache) => {

  // GET /api/app/products
  app.get('/api/app/products', async (req, res) => {
    try {
      const { limit = 50, collection_id, vendor, product_type, page_info } = req.query;
      const token = await getShopifyToken();
      let url;
      let collectionTotal = null;

      if (page_info) {
        // Cursor pagination for all products (no fields param allowed)
        url = `https://${SHOPIFY_DOMAIN}/admin/api/2024-04/products.json?limit=${limit}&page_info=${encodeURIComponent(page_info)}`;
      } else if (collection_id) {
        // Use Storefront API for collection products (returns full price/variant data)
        const storefrontToken = process.env.SHOPIFY_STOREFRONT_TOKEN;
        const afterCursor = page_info ? `, after: \"\"\" + page_info + "\"\"\"` : '';
        const gqlQuery = `{
          collection(id: \"gid://shopify/Collection/${collection_id}\") {
            title
            products(first: ${limit}${afterCursor}) {
              pageInfo { hasNextPage endCursor }
              nodes {
                id title handle productType vendor tags
                images(first: 5) { nodes { url } }
                priceRange { minVariantPrice { amount } }
                compareAtPriceRange { minVariantPrice { amount } }
                variants(first: 1) { nodes { id price compareAtPrice availableForSale } }
              }
            }
          }
        }`;

        const gqlResult = await axios.post(
          `https://${SHOPIFY_DOMAIN}/api/2024-04/graphql.json`,
          { query: gqlQuery },
          { headers: { 'Content-Type': 'application/json', 'X-Shopify-Storefront-Access-Token': storefrontToken } }
        );

        const colData = gqlResult.data?.data?.collection;
        if (!colData) return res.json({ success: true, products: [], nextPageInfo: null, total: 0 });

        const nodes = colData.products?.nodes || [];
        const pageInfo = colData.products?.pageInfo;

        const sfProducts = nodes.map(p => {
          const variantId = p.variants?.nodes?.[0]?.id?.replace('gid://shopify/ProductVariant/', '');
          const price     = p.variants?.nodes?.[0]?.price || p.priceRange?.minVariantPrice?.amount || '0';
          const compare   = p.variants?.nodes?.[0]?.compareAtPrice || p.compareAtPriceRange?.minVariantPrice?.amount || null;
          const numId     = p.id?.replace('gid://shopify/Product/', '');
          return {
            id:          parseInt(numId),
            title:       p.title,
            handle:      p.handle,
            type:        p.productType,
            vendor:      p.vendor,
            tags:        p.tags?.join(', '),
            price:       price,
            comparePrice: compare && compare !== '0.0' ? compare : null,
            image:       p.images?.nodes?.[0]?.url || null,
            images:      (p.images?.nodes || []).map(i => i.url),
            inStock:     p.variants?.nodes?.[0]?.availableForSale !== false,
            variantId:   parseInt(variantId),
          };
        });

        // Get total count
        try {
          const countData = await shopifyGet(`products/count.json?collection_id=${collection_id}`);
          collectionTotal = countData.count;
        } catch(_) {}

        return res.json({
          success: true,
          products: sfProducts,
          count: sfProducts.length,
          nextPageInfo: pageInfo?.hasNextPage ? pageInfo.endCursor : null,
          total: collectionTotal,
        });
      } else {
        let q = `products.json?limit=${limit}&status=active&fields=id,title,handle,variants,images,product_type,vendor,tags`;
        if (vendor)       q += `&vendor=${encodeURIComponent(vendor)}`;
        if (product_type) q += `&product_type=${encodeURIComponent(product_type)}`;
        url = `https://${SHOPIFY_DOMAIN}/admin/api/2024-04/${q}`;
      }

      const result = await axios.get(url, { headers: { 'X-Shopify-Access-Token': token } });
      const data   = result.data;

      const nextPageInfo = extractNextCursor(result.headers?.link || result.headers?.Link || '');

      const products = (data.products || []).map(p => ({
        id:          p.id,
        title:       p.title,
        handle:      p.handle,
        type:        p.product_type,
        vendor:      p.vendor,
        tags:        p.tags,
        price:       p.variants?.[0]?.price || '0',
        comparePrice: p.variants?.[0]?.compare_at_price || null,
        image:       p.images?.[0]?.src || null,
        images:      (p.images || []).map(i => i.src),
        inStock:     p.variants?.some(v => v.inventory_quantity > 0 || v.inventory_management === null),
        variantId:   p.variants?.[0]?.id,
      }));

      // Get total for non-collection first page
      let total = collectionTotal;
      if (!total && !page_info && !collection_id) {
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

  // GET /api/app/collections
  app.get('/api/app/collections', async (req, res) => {
    try {
      const [customData, smartData] = await Promise.all([
        shopifyGet('custom_collections.json?limit=50&fields=id,title,handle,image'),
        shopifyGet('smart_collections.json?limit=50&fields=id,title,handle,image'),
      ]);
      const custom = (customData.custom_collections || []).map(c => ({ id: c.id, title: c.title, handle: c.handle, image: c.image?.src || null }));
      const smart  = (smartData.smart_collections  || []).map(c => ({ id: c.id, title: c.title, handle: c.handle, image: c.image?.src || null }));
      res.json({ success: true, collections: [...custom, ...smart] });
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

  // GET /api/app/menu
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
        { headers: { 'Content-Type': 'application/json', 'X-Shopify-Storefront-Access-Token': storefrontToken } }
      );
      const menu = result.data?.data?.menu;
      if (!menu) return res.json({ success: true, items: [] });
      res.json({ success: true, title: menu.title, items: menu.items || [] });
    } catch (err) {
      console.error('[SHOP] menu error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to fetch menu.' });
    }
  });

  // GET /api/app/get-storefront-token
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

  // POST /api/app/cart/create
  app.post('/api/app/cart/create', async (req, res) => {
    try {
      const { lines } = req.body;
      if (!lines?.length) return res.status(400).json({ success: false, message: 'No items.' });
      const storefrontToken = process.env.SHOPIFY_STOREFRONT_TOKEN;
      const query = `
        mutation cartCreate($input: CartInput!) {
          cartCreate(input: $input) {
            cart { id checkoutUrl }
            userErrors { field message }
          }
        }
      `;
      const variables = {
        input: {
          lines: lines.map(l => ({
            merchandiseId: `gid://shopify/ProductVariant/${l.variantId}`,
            quantity: l.quantity,
          })),
          attributes: [{ key: 'source', value: 'whp-app' }],
        }
      };
      const result = await axios.post(
        `https://${SHOPIFY_DOMAIN}/api/2024-04/graphql.json`,
        { query, variables },
        { headers: { 'Content-Type': 'application/json', 'X-Shopify-Storefront-Access-Token': storefrontToken } }
      );
      const cart = result.data?.data?.cartCreate?.cart;
      if (!cart) return res.status(400).json({ success: false, message: 'Cart creation failed.' });
      res.json({ success: true, checkoutUrl: cart.checkoutUrl, cartId: cart.id });
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
