// routes/mobile-shop.js — Shopify product proxy for mobile app
// Uses Admin API token (server-side only — never exposed to app)

const axios = require('axios');

const SHOPIFY_DOMAIN        = process.env.SHOPIFY_SHOP_DOMAIN;
const SHOPIFY_CLIENT_ID     = process.env.SHOPIFY_MOBILE_CLIENT_ID;
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_MOBILE_CLIENT_SECRET;

// ── Token cache (same pattern as app-auth.js) ────────────
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
  return _token;
}

async function shopifyGet(path) {
  const token = await getShopifyToken();
  const res = await axios.get(`https://${SHOPIFY_DOMAIN}/admin/api/2024-04/${path}`, {
    headers: { 'X-Shopify-Access-Token': token }
  });
  return res.data;
}

// ════════════════════════════════════════════════════════
module.exports = (app, cache) => {

  // ── GET /api/app/products ────────────────────────────
  // Query params: limit, page_info, collection_id, vendor, product_type
  app.get('/api/app/products', async (req, res) => {
    try {
      const { limit = 20, page_info, collection_id, vendor, product_type } = req.query;

      let url = `products.json?limit=${limit}&status=active&fields=id,title,handle,variants,images,product_type,vendor,tags`;
      if (page_info)     url += `&page_info=${page_info}`;
      if (vendor)        url += `&vendor=${encodeURIComponent(vendor)}`;
      if (product_type)  url += `&product_type=${encodeURIComponent(product_type)}`;

      let data;
      if (collection_id) {
        // Fetch products from a specific collection
        data = await shopifyGet(`collections/${collection_id}/products.json?limit=${limit}&fields=id,title,handle,variants,images,product_type,vendor,tags`);
      } else {
        data = await shopifyGet(url);
      }

      const products = (data.products || []).map(p => ({
        id:       p.id,
        title:    p.title,
        handle:   p.handle,
        type:     p.product_type,
        vendor:   p.vendor,
        tags:     p.tags,
        price:    p.variants?.[0]?.price || '0',
        comparePrice: p.variants?.[0]?.compare_at_price || null,
        image:    p.images?.[0]?.src || null,
        images:   (p.images || []).map(i => i.src),
        inStock:  p.variants?.some(v => v.inventory_quantity > 0 || v.inventory_management === null),
        variantId: p.variants?.[0]?.id,
      }));

      res.json({ success: true, products, count: products.length });
    } catch (err) {
      console.error('[SHOP] products error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to fetch products.' });
    }
  });


  // ── GET /api/app/collections ─────────────────────────
  app.get('/api/app/collections', async (req, res) => {
    try {
      const data = await shopifyGet('custom_collections.json?limit=20&fields=id,title,handle,image');
      const collections = (data.custom_collections || []).map(c => ({
        id:     c.id,
        title:  c.title,
        handle: c.handle,
        image:  c.image?.src || null,
      }));
      res.json({ success: true, collections });
    } catch (err) {
      console.error('[SHOP] collections error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to fetch collections.' });
    }
  });


  // ── GET /api/app/products/:id ────────────────────────
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
            id:     v.id,
            title:  v.title,
            price:  v.price,
            inStock: v.inventory_quantity > 0 || v.inventory_management === null,
          })),
        }
      });
    } catch (err) {
      console.error('[SHOP] product detail error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to fetch product.' });
    }
  });

};

  // ── GET /api/app/menu ────────────────────────────────
  // Fetch Shopify navigation menu via GraphQL
  app.get('/api/app/menu', async (req, res) => {
    try {
      const token = await getShopifyToken();
      const handle = req.query.handle || 'main-menu';

      const query = `{
        menu(handle: "${handle}") {
          title
          items {
            id title url
            items {
              id title url
              items {
                id title url
              }
            }
          }
        }
      }`;

      const result = await axios.post(
        `https://${SHOPIFY_DOMAIN}/admin/api/2024-04/graphql.json`,
        { query },
        { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
      );

      const menu = result.data?.data?.menu;
      if (!menu) return res.json({ success: true, items: [] });

      res.json({ success: true, title: menu.title, items: menu.items || [] });
    } catch (err) {
      console.error('[SHOP] menu error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to fetch menu.' });
    }
  });
