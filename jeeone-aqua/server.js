/**
 * JeeOne Aqua — Backend API Server
 * Serves both the Android app and the website.
 * Storage: JSON files in ./data (easy to inspect, no DB setup).
 * Run: node server.js  (PORT env, default 8081)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

const PORT = process.env.PORT || 8081;
const DATA = path.join(__dirname, 'data');

// ---------- Contact / brand config (Sam's real details) ----------
const CONFIG = {
  brand: 'JeeOne Aqua',
  supportEmail: 'jeeoneaqua@gmail.com',
  supportPhone: '+91 97177 69977',
  supportPhoneRaw: '919717769977',
  whatsapp: 'https://wa.me/919717769977',
  currency: 'INR',
  version: '1.0.0'
};

// ---------- Storage helpers ----------
function readJson(name, fallback) {
  try {
    return JSON.parse(fs.readFileSync(path.join(DATA, name + '.json'), 'utf8'));
  } catch (e) { return fallback; }
}
function writeJson(name, data) {
  fs.writeFileSync(path.join(DATA, name + '.json'), JSON.stringify(data, null, 2));
}
function readBody(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', c => { b += c; if (b.length > 2e6) req.destroy(); });
    req.on('end', () => {
      try { resolve(JSON.parse(b || '{}')); }
      catch (e) { resolve({}); }
    });
  });
}
function uid(prefix) {
  return (prefix || '') + crypto.randomBytes(4).toString('hex').toUpperCase();
}

// ---------- HTTP helpers ----------
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(body);
}
function ok(res, data) { send(res, 200, { ok: true, data }); }
function fail(res, code, msg) { send(res, code, { ok: false, error: msg }); }

// Admin auth with demo login
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'jeeone123';
const adminTokens = new Set();

function getToken(req) {
  const h = req.headers['authorization'] || '';
  return h.startsWith('Bearer ') ? h.slice(7) : null;
}
function requireAdmin(req, res) {
  const t = getToken(req);
  if (!t || !adminTokens.has(t)) { fail(res, 401, 'Auth required'); return false; }
  return true;
}
function makeToken() {
  return 'adm_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
}

// ---------- Router ----------
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const p = decodeURIComponent(parsed.pathname);
  const m = req.method;

  // CORS preflight
  if (m === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    return res.end();
  }

  try {
    // ----- Admin panel -----
    if ((p === '/admin' || p === '/admin.html') && m === 'GET') {
      const fs = require('fs');
      const path = require('path');
      const fp = path.join(__dirname, 'admin.html');
      if (fs.existsSync(fp)) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end(fs.readFileSync(fp));
      }
      return fail(res, 404, 'Admin panel not found');
    }

    // ----- Health & config -----
    if (p === '/api/health' && m === 'GET') {
      return ok(res, { status: 'up', time: new Date().toISOString() });
    }
    if (p === '/api/config' && m === 'GET') {
      return ok(res, CONFIG);
    }

    // ----- Products -----
    if (p === '/api/products' && m === 'GET') {
      return ok(res, readJson('products', []));
    }
    const prodMatch = p.match(/^\/api\/products\/([\w-]+)$/);
    if (prodMatch && m === 'GET') {
      const prod = readJson('products', []).find(x => x.id === prodMatch[1]);
      if (!prod) return fail(res, 404, 'Product not found');
      return ok(res, prod);
    }
    if (p === '/api/products' && m === 'POST') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req);
      const products = readJson('products', []);
      const np = { id: body.id || uid('p'), ...body };
      products.push(np); writeJson('products', products);
      return ok(res, np);
    }
    if (prodMatch && m === 'PUT') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req);
      const products = readJson('products', []);
      const i = products.findIndex(x => x.id === prodMatch[1]);
      if (i < 0) return fail(res, 404, 'Product not found');
      products[i] = { ...products[i], ...body, id: prodMatch[1] };
      writeJson('products', products);
      return ok(res, products[i]);
    }
    if (prodMatch && m === 'DELETE') {
      if (!requireAdmin(req, res)) return;
      let products = readJson('products', []);
      products = products.filter(x => x.id !== prodMatch[1]);
      writeJson('products', products);
      return ok(res, { deleted: prodMatch[1] });
    }

    // ----- Orders -----
    if (p === '/api/orders' && m === 'GET') {
      let orders = readJson('orders', []);
      const phone = parsed.query.phone;
      if (phone) orders = orders.filter(o => o.phone === phone);
      return ok(res, orders);
    }
    if (p === '/api/orders' && m === 'POST') {
      const body = await readBody(req);
      const orders = readJson('orders', []);
      const order = {
        id: 'JEA-' + Math.floor(100000 + Math.random() * 900000),
        items: body.items || [],
        subtotal: body.subtotal || 0,
        discount: body.discount || 0,
        delivery: body.delivery || 0,
        total: body.total || 0,
        name: body.name || '', phone: body.phone || '',
        address: body.address || '', slot: body.slot || '',
        payment: body.payment || 'Cash on Delivery',
        coupon: body.coupon || null,
        placedAt: new Date().toISOString(),
        status: 'Confirmed',
        timeline: [{ status: 'Placed', at: new Date().toISOString() }]
      };
      orders.unshift(order); writeJson('orders', orders);
      // Notify user
      const notifs = readJson('notifications', []);
      notifs.unshift({
        id: uid('n'), phone: order.phone,
        title: 'Order placed!', body: `Your order ${order.id} is confirmed.`,
        at: new Date().toISOString(), read: false, type: 'order'
      });
      writeJson('notifications', notifs);
      return ok(res, { orderId: order.id, order });
    }
    const orderMatch = p.match(/^\/api\/orders\/([\w-]+)$/);
    if (orderMatch && m === 'GET') {
      const order = readJson('orders', []).find(x => x.id === orderMatch[1]);
      if (!order) return fail(res, 404, 'Order not found');
      return ok(res, order);
    }
    const statusMatch = p.match(/^\/api\/orders\/([\w-]+)\/status$/);
    if (statusMatch && m === 'PATCH') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req);
      const orders = readJson('orders', []);
      const o = orders.find(x => x.id === statusMatch[1]);
      if (!o) return fail(res, 404, 'Order not found');
      o.status = body.status || o.status;
      o.timeline = o.timeline || [];
      o.timeline.push({ status: o.status, at: new Date().toISOString() });
      writeJson('orders', orders);
      return ok(res, o);
    }

    // ----- Admin login (demo) -----
    if (p === '/api/admin/login' && m === 'POST') {
      const body = await readBody(req);
      if (body.username === ADMIN_USER && body.password === ADMIN_PASS) {
        const token = makeToken();
        adminTokens.add(token);
        return ok(res, { token, username: ADMIN_USER });
      }
      return fail(res, 401, 'Invalid username or password');
    }

    // ----- Auth (OTP demo) -----
    if (p === '/api/auth/otp' && m === 'POST') {
      const body = await readBody(req);
      const phone = (body.phone || '').replace(/\D/g, '').slice(-10);
      if (phone.length !== 10) return fail(res, 400, 'Valid 10-digit phone required');
      const otp = '123456'; // demo OTP
      const users = readJson('users', []);
      let u = users.find(x => x.phone === phone);
      if (!u) { u = { phone, name: '', createdAt: new Date().toISOString() }; users.push(u); }
      u.pendingOtp = otp; u.otpAt = Date.now();
      writeJson('users', users);
      return ok(res, { sent: true, demoOtp: otp });
    }
    if (p === '/api/auth/verify' && m === 'POST') {
      const body = await readBody(req);
      const phone = (body.phone || '').replace(/\D/g, '').slice(-10);
      const users = readJson('users', []);
      const u = users.find(x => x.phone === phone);
      if (!u || u.pendingOtp !== body.otp) return fail(res, 400, 'Invalid OTP');
      u.token = uid('tkn_'); u.pendingOtp = null;
      if (body.name) u.name = body.name;
      writeJson('users', users);
      return ok(res, { token: u.token, phone: u.phone, name: u.name || '' });
    }
    if (p === '/api/users/me' && m === 'GET') {
      const t = getToken(req);
      const u = readJson('users', []).find(x => x.token === t);
      if (!u) return fail(res, 401, 'Invalid token');
      return ok(res, { phone: u.phone, name: u.name || '' });
    }

    // ----- Reviews -----
    if (p === '/api/reviews' && m === 'GET') {
      const pid = parsed.query.product || '';
      let rv = readJson('reviews', []);
      if (pid) rv = rv.filter(r => r.product === pid);
      return ok(res, rv);
    }
    if (p === '/api/reviews' && m === 'POST') {
      const body = await readBody(req);
      const rv = readJson('reviews', []);
      const r = { id: uid('r'), ...body, at: new Date().toISOString() };
      rv.unshift(r); writeJson('reviews', rv);
      return ok(res, r);
    }

    // ----- Coupons -----
    if (p === '/api/coupons' && m === 'GET') {
      const saved = readJson('coupons', null);
      if (saved) return ok(res, saved);
      return ok(res, [
        { code: 'WELCOME20', title: '20% off first order', desc: 'New customers • Min order ₹149', active: true },
        { code: 'JAR10', title: '₹10 off 20L jar', desc: 'On every 20L jar refill', active: true },
        { code: 'FAMILY15', title: '15% off Family Combo', desc: 'On Family Combo pack', active: true }
      ]);
    }
    if (p === '/api/coupons' && m === 'POST') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req);
      const cp = readJson('coupons', []);
      cp.push({ ...body, active: true });
      writeJson('coupons', cp);
      return ok(res, body);
    }

    // ----- Feedback -----
    if (p === '/api/feedback' && m === 'POST') {
      const body = await readBody(req);
      const fb = readJson('feedback', []);
      fb.unshift({ id: uid('f'), ...body, at: new Date().toISOString() });
      writeJson('feedback', fb);
      return ok(res, { received: true });
    }
    if (p === '/api/feedback' && m === 'GET') {
      if (!requireAdmin(req, res)) return;
      return ok(res, readJson('feedback', []));
    }

    // ----- Notifications -----
    if (p === '/api/notifications' && m === 'GET') {
      let nt = readJson('notifications', []);
      const phone = parsed.query.phone;
      if (phone) nt = nt.filter(n => !n.phone || n.phone === phone);
      return ok(res, nt.slice(0, 50));
    }
    if (p === '/api/notifications' && m === 'POST') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req);
      const nt = readJson('notifications', []);
      const n = { id: uid('n'), read: false, at: new Date().toISOString(), ...body };
      nt.unshift(n); writeJson('notifications', nt.slice(0, 200));
      return ok(res, n);
    }

    // ----- Subscriptions -----
    if (p === '/api/subscriptions' && m === 'GET') {
      let subs = readJson('subscriptions', []);
      const phone = parsed.query.phone;
      if (phone) subs = subs.filter(s => s.phone === phone);
      return ok(res, subs);
    }
    if (p === '/api/subscriptions' && m === 'POST') {
      const body = await readBody(req);
      const subs = readJson('subscriptions', []);
      const sub = { id: uid('sub'), status: 'active', createdAt: new Date().toISOString(),
        nextDelivery: body.nextDelivery || null, ...body };
      subs.push(sub); writeJson('subscriptions', subs);
      return ok(res, sub);
    }
    const subMatch = p.match(/^\/api\/subscriptions\/([\w-]+)$/);
    if (subMatch && m === 'PUT') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req);
      const subs = readJson('subscriptions', []);
      const i = subs.findIndex(x => x.id === subMatch[1]);
      if (i < 0) return fail(res, 404, 'Subscription not found');
      subs[i] = { ...subs[i], ...body, id: subMatch[1] };
      writeJson('subscriptions', subs);
      return ok(res, subs[i]);
    }
    if (subMatch && m === 'DELETE') {
      if (!requireAdmin(req, res)) return;
      let subs = readJson('subscriptions', []);
      subs = subs.filter(x => x.id !== subMatch[1]);
      writeJson('subscriptions', subs);
      return ok(res, { deleted: subMatch[1] });
    }

    // ----- Delivery Slots -----
    if (p === '/api/slots' && m === 'GET') return ok(res, readJson('slots', [
      { id: 's1', label: 'Morning (7-11 AM)', active: true },
      { id: 's2', label: 'Afternoon (12-4 PM)', active: true },
      { id: 's3', label: 'Evening (5-9 PM)', active: true }
    ]));
    if (p === '/api/slots' && m === 'POST') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req);
      const slots = readJson('slots', []);
      const s = { id: uid('s'), active: true, ...body };
      slots.push(s); writeJson('slots', slots);
      return ok(res, s);
    }
    const slotMatch = p.match(/^\/api\/slots\/([\w-]+)$/);
    if (slotMatch && (m === 'PUT' || m === 'DELETE')) {
      if (!requireAdmin(req, res)) return;
      let slots = readJson('slots', []);
      if (m === 'DELETE') { slots = slots.filter(x => x.id !== slotMatch[1]); }
      else {
        const body = await readBody(req);
        const i = slots.findIndex(x => x.id === slotMatch[1]);
        if (i < 0) return fail(res, 404, 'Slot not found');
        slots[i] = { ...slots[i], ...body, id: slotMatch[1] };
      }
      writeJson('slots', slots);
      return ok(res, { done: true });
    }

    // ----- Delivery Boys -----
    if (p === '/api/delivery-boys' && m === 'GET') {
      if (!requireAdmin(req, res)) return;
      return ok(res, readJson('deliveryBoys', []));
    }
    if (p === '/api/delivery-boys' && m === 'POST') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req);
      const boys = readJson('deliveryBoys', []);
      const b = { id: uid('d'), active: true, ...body };
      boys.push(b); writeJson('deliveryBoys', boys);
      return ok(res, b);
    }
    const boyMatch = p.match(/^\/api\/delivery-boys\/([\w-]+)$/);
    if (boyMatch && (m === 'PUT' || m === 'DELETE')) {
      if (!requireAdmin(req, res)) return;
      let boys = readJson('deliveryBoys', []);
      if (m === 'DELETE') { boys = boys.filter(x => x.id !== boyMatch[1]); }
      else {
        const body = await readBody(req);
        const i = boys.findIndex(x => x.id === boyMatch[1]);
        if (i < 0) return fail(res, 404, 'Not found');
        boys[i] = { ...boys[i], ...body, id: boyMatch[1] };
      }
      writeJson('deliveryBoys', boys);
      return ok(res, { done: true });
    }

    // ----- Categories -----
    if (p === '/api/categories' && m === 'GET') return ok(res, readJson('categories', [
      { id: 'c1', name: 'Bottles', icon: 'bottle' },
      { id: 'c2', name: 'Jars', icon: 'jar' },
      { id: 'c3', name: 'Dispensers', icon: 'dispenser' }
    ]));
    if (p === '/api/categories' && m === 'POST') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req);
      const cats = readJson('categories', []);
      const c = { id: uid('c'), ...body };
      cats.push(c); writeJson('categories', cats);
      return ok(res, c);
    }
    const catMatch = p.match(/^\/api\/categories\/([\w-]+)$/);
    if (catMatch && m === 'DELETE') {
      if (!requireAdmin(req, res)) return;
      const cats = readJson('categories', []).filter(x => x.id !== catMatch[1]);
      writeJson('categories', cats);
      return ok(res, { deleted: catMatch[1] });
    }

    // ----- Banners -----
    if (p === '/api/banners' && m === 'GET') return ok(res, readJson('banners', []));
    if (p === '/api/banners' && m === 'POST') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req);
      const banners = readJson('banners', []);
      const b = { id: uid('b'), active: true, ...body };
      banners.push(b); writeJson('banners', banners);
      return ok(res, b);
    }
    const bannerMatch = p.match(/^\/api\/banners\/([\w-]+)$/);
    if (bannerMatch && (m === 'PUT' || m === 'DELETE')) {
      if (!requireAdmin(req, res)) return;
      let banners = readJson('banners', []);
      if (m === 'DELETE') { banners = banners.filter(x => x.id !== bannerMatch[1]); }
      else {
        const body = await readBody(req);
        const i = banners.findIndex(x => x.id === bannerMatch[1]);
        if (i < 0) return fail(res, 404, 'Not found');
        banners[i] = { ...banners[i], ...body, id: bannerMatch[1] };
      }
      writeJson('banners', banners);
      return ok(res, { done: true });
    }

    // ----- Inventory -----
    if (p === '/api/inventory' && m === 'GET') {
      if (!requireAdmin(req, res)) return;
      return ok(res, readJson('inventory', []));
    }
    if (p === '/api/inventory' && m === 'POST') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req);
      const inv = readJson('inventory', []);
      const i = inv.findIndex(x => x.productId === body.productId);
      const item = { productId: body.productId, stock: body.stock || 0, lowAt: body.lowAt || 10, updatedAt: new Date().toISOString() };
      if (i >= 0) inv[i] = item; else inv.push(item);
      writeJson('inventory', inv);
      return ok(res, item);
    }

    // ----- Customers (admin view of users) -----
    if (p === '/api/customers' && m === 'GET') {
      if (!requireAdmin(req, res)) return;
      const users = readJson('users', []);
      const orders = readJson('orders', []);
      const customers = users.map(u => {
        const uOrders = orders.filter(o => o.phone === u.phone);
        return { phone: u.phone, name: u.name || '',
          orders: uOrders.length,
          spent: uOrders.reduce((s, o) => s + (o.total || 0), 0),
          joined: u.createdAt || '' };
      });
      return ok(res, customers);
    }

    // ----- Settings -----
    if (p === '/api/settings' && m === 'GET') return ok(res, readJson('settings', {
      deliveryFee: 0, minOrder: 0, freeAbove: 199,
      storeName: 'JeeOne Aqua', supportPhone: '+91 97177 69977',
      supportEmail: 'jeeoneaqua@gmail.com', codEnabled: true, onlineEnabled: true
    }));
    if (p === '/api/settings' && m === 'PUT') {
      if (!requireAdmin(req, res)) return;
      const body = await readBody(req);
      const cur = readJson('settings', {});
      const updated = { ...cur, ...body };
      writeJson('settings', updated);
      return ok(res, updated);
    }

    // ----- Reports -----
    if (p === '/api/reports/summary' && m === 'GET') {
      if (!requireAdmin(req, res)) return;
      const orders = readJson('orders', []);
      const now = new Date();
      const today = now.toISOString().slice(0, 10);
      const thisMonth = today.slice(0, 7);
      const tOrders = orders.filter(o => (o.placedAt || '').slice(0, 10) === today);
      const mOrders = orders.filter(o => (o.placedAt || '').slice(0, 7) === thisMonth);
      const byStatus = {};
      orders.forEach(o => { byStatus[o.status] = (byStatus[o.status] || 0) + 1; });
      return ok(res, {
        today: { orders: tOrders.length, revenue: tOrders.reduce((s, o) => s + (o.total || 0), 0) },
        month: { orders: mOrders.length, revenue: mOrders.reduce((s, o) => s + (o.total || 0), 0) },
        all: { orders: orders.length, revenue: orders.reduce((s, o) => s + (o.total || 0), 0) },
        byStatus
      });
    }

    // ----- Assign delivery boy to order -----
    if (p.match(/^\/api\/orders\/([\w-]+)\/assign$/) && m === 'PATCH') {
      if (!requireAdmin(req, res)) return;
      const oid = p.match(/^\/api\/orders\/([\w-]+)\/assign$/)[1];
      const body = await readBody(req);
      const orders = readJson('orders', []);
      const o = orders.find(x => x.id === oid);
      if (!o) return fail(res, 404, 'Order not found');
      o.deliveryBoy = body.deliveryBoy || null;
      o.timeline.push({ status: 'Assigned to ' + (body.deliveryBoy || 'delivery'), at: new Date().toISOString() });
      writeJson('orders', orders);
      return ok(res, o);
    }

    return fail(res, 404, 'Not found: ' + p);
  } catch (e) {
    console.error(e);
    return fail(res, 500, 'Server error');
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`JeeOne Aqua Backend live on port ${PORT}`);
  console.log(`Health: http://localhost:${PORT}/api/health`);
});
