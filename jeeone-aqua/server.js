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
