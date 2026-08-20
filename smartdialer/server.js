const express = require('express');
const admin = require('firebase-admin');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const app = express();

// Force parse ALL incoming requests as JSON, even if Android misses Content-Type header
app.use(express.json({ limit: '256kb', type: '*/*' }));
app.use(express.urlencoded({ extended: true, limit: '256kb' }));
app.use(cors());

// Diagnostic Logger: Prints exact payload received from Android app
app.use((req, res, next) => {
    if (req.originalUrl.includes('/api/')) {
        console.log(`[C2 DEBUG] ${req.method} ${req.originalUrl} | Body:`, JSON.stringify(req.body));
    }
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// FIREBASE INIT
// ============================================================
let db;
let messaging = null;
let isFirebaseInitialized = false;

try {
    let serviceAccount;
    if (process.env.SERVICE_ACCOUNT_KEY_BASE64) {
        serviceAccount = JSON.parse(Buffer.from(process.env.SERVICE_ACCOUNT_KEY_BASE64, 'base64').toString('utf-8'));
    } else {
        throw new Error("SERVICE_ACCOUNT_KEY_BASE64 missing in Master .env file.");
    }
    const databaseURL = process.env.FIREBASE_DATABASE_URL || `https://${serviceAccount.project_id}-default-rtdb.firebaseio.com`;
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        databaseURL: databaseURL
    });
    db = admin.database();
    try { messaging = admin.messaging(); } catch (_) { messaging = null; }
    isFirebaseInitialized = true;
    console.log(`[C2 Master Node] Firebase Admin SDK Initialized. DB: ${databaseURL}`);
} catch (error) {
    console.error("[C2 Master Node ERROR] Firebase init failed:", error.message);
    console.warn("[C2 Master Node WARN] DEGRADED MODE.");
    db = {
        ref: () => ({
            once: async () => ({ val: () => ({}) }),
            set: async () => {}, update: async () => {}, remove: async () => {},
            push: () => ({ key: 'stub' }), child: () => this.ref()
        })
    };
}

const checkFirebase = (req, res, next) => {
    if (!isFirebaseInitialized) {
        return res.status(500).json({ success: false, message: "Firebase is offline." });
    }
    next();
};

// ============================================================
// BASIC RATE LIMITER (in-memory, per-IP)
// ============================================================
const rateLimitMap = new Map();
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX_PER_WINDOW = 100;

function rateLimit(req, res, next) {
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').toString();
    const now = Date.now();
    let entry = rateLimitMap.get(ip);
    if (!entry || now - entry.start > RATE_WINDOW_MS) {
        entry = { start: now, count: 0 };
        rateLimitMap.set(ip, entry);
    }
    entry.count++;
    if (entry.count > RATE_MAX_PER_WINDOW) {
        return res.status(429).json({ success: false, message: "Too many requests. Slow down." });
    }
    next();
}

app.use(rateLimit);

// ============================================================
// INPUT VALIDATION HELPERS (EASED FOR LOGIN)
// ============================================================
function isValidUsername(u) { return u != null && String(u).trim().length >= 1; }
function isValidPassword(p) { return p != null && String(p).length >= 1; }
function isValidStatus(s) { return s != null && ['ACTIVE','SUSPENDED','DISABLED','REVOKED'].includes(String(s).toUpperCase()); }

// ============================================================
// ADMIN SESSION MANAGEMENT (server-side, expiring, revocable)
// ============================================================
const ADMIN_SESSION_TTL_MS = 4 * 60 * 60 * 1000; // 4 hours

async function createAdminSession(username, ip) {
    const token = crypto.randomBytes(48).toString('hex');
    const now = Date.now();
    const session = {
        username,
        created_at: now,
        expires_at: now + ADMIN_SESSION_TTL_MS,
        ip,
        revoked: false
    };
    await db.ref(`admin_sessions/${token}`).set(session);
    return token;
}

async function verifyAdminSession(token) {
    if (!token) return null;
    const snap = await db.ref(`admin_sessions/${token}`).once('value');
    const s = snap.val();
    if (!s) return null;
    if (s.revoked) return null;
    if (Date.now() > s.expires_at) {
        await db.ref(`admin_sessions/${token}`).remove();
        return null;
    }
    return s;
}

async function revokeAdminSession(token) {
    if (!token) return;
    try { await db.ref(`admin_sessions/${token}`).update({ revoked: true }); } catch (_) {}
}

// ============================================================
// AUDIT LOG
// ============================================================
async function auditLog(admin, action, username, deviceId, reason, result) {
    try {
        await db.ref('audit_log').push({
            admin: admin || 'unknown',
            action,
            username: username || '',
            device_id: deviceId || '',
            timestamp: Date.now(),
            reason: reason || '',
            result: result || 'SUCCESS'
        });
    } catch (e) { console.error('[audit] failed', e.message); }
}

// ============================================================
// ADMIN LOGIN (bcrypt + session token)
// ============================================================
app.post('/api/admin/login', checkFirebase, async (req, res) => {
    const username = req.body.username || req.body.user;
    const password = req.body.password || req.body.pass;
    const masterUser = process.env.ADMIN_USERNAME;
    const masterHash = process.env.ADMIN_PASSWORD_HASH;     // bcrypt hash (preferred)
    const masterPlain = process.env.ADMIN_PASSWORD;          // legacy plaintext (deprecated)

    if (!masterUser || (!masterHash && !masterPlain)) {
        return res.status(500).json({ success: false, message: "Admin credentials not configured." });
    }
    if (username !== masterUser) {
        await auditLog('unknown', 'LOGIN_ATTEMPT', username, '', 'Bad username', 'FAILED');
        return res.status(401).json({ success: false, message: "Invalid Admin Credentials" });
    }

    let ok = false;
    if (masterHash) {
        try { ok = await bcrypt.compare(password, masterHash); } catch (_) { ok = false; }
    } else {
        // Legacy fallback (will be removed once all envs set ADMIN_PASSWORD_HASH)
        ok = (password === masterPlain);
    }
    if (!ok) {
        await auditLog(username, 'LOGIN_ATTEMPT', username, '', 'Bad password', 'FAILED');
        return res.status(401).json({ success: false, message: "Invalid Admin Credentials" });
    }

    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString();
    const token = await createAdminSession(username, ip);
    await auditLog(username, 'LOGIN', username, '', '', 'SUCCESS');
    res.json({ success: true, token });
});

app.post('/api/admin/logout', checkFirebase, async (req, res) => {
    const token = req.headers['authorization'];
    const s = await verifyAdminSession(token);
    if (s) await auditLog(s.username, 'LOGOUT', '', '', '', 'SUCCESS');
    await revokeAdminSession(token);
    res.json({ success: true });
});

app.get('/api/admin/me', checkFirebase, async (req, res) => {
    const token = req.headers['authorization'];
    const s = await verifyAdminSession(token);
    if (!s) return res.status(403).json({ success: false, message: "Unauthorized" });
    res.json({ success: true, username: s.username, expires_at: s.expires_at });
});

// Authorization middleware
const verifyAdmin = async (req, res, next) => {
    const token = req.headers['authorization'];
    const s = await verifyAdminSession(token);
    if (!s) return res.status(403).json({ success: false, message: "Unauthorized Access" });
    req.adminUser = s.username;
    next();
};

// ============================================================
// USER HELPERS
// ============================================================
async function hashPassword(plain) {
    return await bcrypt.hash(plain, 10);
}

async function getUser(username) {
    const snap = await db.ref(`users/${username}`).once('value');
    return snap.val();
}

// Migrate legacy fields on-the-fly
async function migrateLegacyUser(username, user) {
    if (!user) return user;
    const updates = {};
    if (user.status === undefined) {
        // is_blocked=true (legacy) -> SUSPENDED; otherwise ACTIVE
        updates.status = user.is_blocked ? 'SUSPENDED' : 'ACTIVE';
    }
    if (user.session_version === undefined) updates.session_version = 0;
    if (user.device_binding_enabled === undefined) updates.device_binding_enabled = true;
    if (user.force_logout === undefined) updates.force_logout = false;
    if (Object.keys(updates).length > 0) {
        await db.ref(`users/${username}`).update(updates);
        Object.assign(user, updates);
    }
    return user;
}

// ============================================================
// ADMIN: USER MANAGEMENT
// ============================================================
app.get('/api/users', verifyAdmin, checkFirebase, async (req, res) => {
    try {
        const snap = await db.ref('users').once('value');
        const users = snap.val() || {};
        // Strip sensitive password fields before returning
        const sanitized = {};
        for (const [u, info] of Object.entries(users)) {
            sanitized[u] = {
                ...info,
                password: undefined,
                password_hash: undefined
            };
        }
        res.json({ success: true, data: sanitized });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/users/:username', verifyAdmin, checkFirebase, async (req, res) => {
    try {
        const u = req.params.username;
        if (!isValidUsername(u)) return res.status(400).json({ success: false, message: "Invalid username" });
        let user = await getUser(u);
        if (!user) return res.status(404).json({ success: false, message: "Not found" });
        user = await migrateLegacyUser(u, user);
        delete user.password;
        delete user.password_hash;
        // Fetch last 10 audit entries for this user
        const auditSnap = await db.ref('audit_log').orderByChild('username').equalTo(u).limitToLast(10).once('value');
        const audit = [];
        auditSnap.forEach(cs => { audit.push(cs.val()); });
        res.json({ success: true, data: { user, audit: audit.reverse() } });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/users/create', verifyAdmin, checkFirebase, async (req, res) => {
    const username = req.body.username || req.body.user;
    const password = req.body.password || req.body.pass;
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    if (!isValidPassword(password)) return res.status(400).json({ success: false, message: "Invalid password" });
    try {
        const existing = await getUser(username);
        if (existing) return res.status(409).json({ success: false, message: "User already exists" });
        const hash = await hashPassword(password);
        await db.ref(`users/${username}`).set({
            password: password,           // legacy compat (will be removed in future migration)
            password_hash: hash,
            status: 'ACTIVE',
            is_blocked: false,            // legacy
            force_logout: false,          // legacy
            fcm_token: '',
            device_binding_enabled: true,
            session_version: 0,
            suspension_reason: '',
            suspended_at: 0,
            suspended_by: ''
        });
        await auditLog(req.adminUser, 'CREATE_ACCOUNT', username, '', '', 'SUCCESS');
        res.json({ success: true, message: `User ${username} created` });
    } catch (e) {
        await auditLog(req.adminUser, 'CREATE_ACCOUNT', username, '', e.message, 'FAILED');
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/users/update-password', verifyAdmin, checkFirebase, async (req, res) => {
    const username = req.body.username || req.body.user;
    const newPassword = req.body.newPassword || req.body.password;
    if (!isValidUsername(username) || !isValidPassword(newPassword)) {
        return res.status(400).json({ success: false, message: "Invalid input" });
    }
    try {
        const hash = await hashPassword(newPassword);
        await db.ref(`users/${username}`).update({
            password: newPassword,        // legacy
            password_hash: hash,
            force_logout: true,           // legacy - force fresh login
            session_version: (await getUser(username))?.session_version + 1 || 0
        });
        await auditLog(req.adminUser, 'UPDATE_PASSWORD', username, '', '', 'SUCCESS');
        res.json({ success: true, message: `Password updated for ${username}` });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/users/delete', verifyAdmin, checkFirebase, async (req, res) => {
    const username = req.body.username || req.body.user;
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    try {
        const u = await getUser(username);
        await db.ref(`users/${username}`).remove();
        await auditLog(req.adminUser, 'DELETE_ACCOUNT', username, u?.device?.device_id || '', '', 'SUCCESS');
        res.json({ success: true, message: `User ${username} deleted.` });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// ============================================================
// ADMIN: SUSPEND / RESTORE / FORCE-LOGOUT / UNBIND
// ============================================================
app.post('/api/admin/suspend', verifyAdmin, checkFirebase, async (req, res) => {
    const username = req.body.username || req.body.user;
    const reason = req.body.reason;
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    try {
        const u = await getUser(username);
        if (!u) return res.status(404).json({ success: false, message: "User not found" });
        const nextSessionVersion = (u.session_version || 0) + 1;
        await db.ref(`users/${username}`).update({
            status: 'SUSPENDED',
            is_blocked: true,                                  // legacy compat
            suspension_reason: reason || '',
            suspended_at: Date.now(),
            suspended_by: req.adminUser,
            force_logout: true,                                // legacy
            session_version: nextSessionVersion
        });
        // Mark session inactive
        if (u.session && u.session.session_id) {
            await db.ref(`users/${username}/session`).update({ active: false });
        }
        // Push FCM-equivalent command
        await pushCommand(username, 'SUSPEND_ACCOUNT', reason || '');
        // Try real FCM if available
        await tryFcm(username, { command: 'SUSPEND_ACCOUNT', reason: reason || '' });

        await auditLog(req.adminUser, 'SUSPEND', username, u.device?.device_id || '', reason || '', 'SUCCESS');
        res.json({ success: true, message: `User ${username} suspended.` });
    } catch (e) {
        await auditLog(req.adminUser, 'SUSPEND', username, '', e.message, 'FAILED');
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/admin/restore', verifyAdmin, checkFirebase, async (req, res) => {
    const username = req.body.username || req.body.user;
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    try {
        const u = await getUser(username);
        if (!u) return res.status(404).json({ success: false, message: "User not found" });
        const nextSessionVersion = (u.session_version || 0) + 1;
        await db.ref(`users/${username}`).update({
            status: 'ACTIVE',
            is_blocked: false,
            suspension_reason: '',
            suspended_at: 0,
            suspended_by: '',
            force_logout: true,                               // force fresh login
            session_version: nextSessionVersion
        });
        // Invalidate old session (preserve device info!)
        await db.ref(`users/${username}/session`).update({
            active: false,
            session_id: null,
            last_verified_at: 0
        });
        await pushCommand(username, 'RESTORE_ACCOUNT', '');
        await tryFcm(username, { command: 'RESTORE_ACCOUNT' });

        await auditLog(req.adminUser, 'RESTORE', username, u.device?.device_id || '', '', 'SUCCESS');
        res.json({ success: true, message: `User ${username} restored. Fresh login required.` });
    } catch (e) {
        await auditLog(req.adminUser, 'RESTORE', username, '', e.message, 'FAILED');
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/admin/force-logout', verifyAdmin, checkFirebase, async (req, res) => {
    const username = req.body.username || req.body.user;
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    try {
        const u = await getUser(username);
        if (!u) return res.status(404).json({ success: false, message: "User not found" });
        const nextSessionVersion = (u.session_version || 0) + 1;
        await db.ref(`users/${username}`).update({
            force_logout: true,                               // legacy compat
            session_version: nextSessionVersion
        });
        if (u.session && u.session.session_id) {
            await db.ref(`users/${username}/session`).update({ active: false });
        }
        await pushCommand(username, 'LOGOUT_NOW', '');
        await tryFcm(username, { command: 'LOGOUT_NOW' });

        await auditLog(req.adminUser, 'FORCE_LOGOUT', username, u.device?.device_id || '', '', 'SUCCESS');
        res.json({ success: true, message: `Force logout sent to ${username}` });
    } catch (e) {
        await auditLog(req.adminUser, 'FORCE_LOGOUT', username, '', e.message, 'FAILED');
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/admin/unbind-device', verifyAdmin, checkFirebase, async (req, res) => {
    const username = req.body.username || req.body.user;
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    try {
        const u = await getUser(username);
        if (!u) return res.status(404).json({ success: false, message: "User not found" });
        const deviceId = u.device?.device_id || '';
        await db.ref(`users/${username}/device`).remove();
        await auditLog(req.adminUser, 'UNBIND_DEVICE', username, deviceId, '', 'SUCCESS');
        res.json({ success: true, message: `Device unbound for ${username}` });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Legacy block endpoint - now routes through suspend/restore
app.post('/api/admin/block', verifyAdmin, checkFirebase, async (req, res) => {
    const username = req.body.username || req.body.user;
    const blockStatus = req.body.blockStatus;
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    try {
        const u = await getUser(username);
        if (!u) return res.status(404).json({ success: false, message: "User not found" });
        if (blockStatus) {
            const nextSessionVersion = (u.session_version || 0) + 1;
            await db.ref(`users/${username}`).update({
                status: 'SUSPENDED',
                is_blocked: true,
                suspension_reason: 'Legacy block',
                suspended_at: Date.now(),
                suspended_by: req.adminUser,
                force_logout: true,
                session_version: nextSessionVersion
            });
            await pushCommand(username, 'SUSPEND_ACCOUNT', 'Legacy block');
            await auditLog(req.adminUser, 'SUSPEND', username, u.device?.device_id || '', 'Legacy block', 'SUCCESS');
            return res.json({ success: true, message: `User ${username} suspended (legacy block=true)` });
        } else {
            const nextSessionVersion = (u.session_version || 0) + 1;
            await db.ref(`users/${username}`).update({
                status: 'ACTIVE',
                is_blocked: false,
                suspension_reason: '',
                suspended_at: 0,
                suspended_by: '',
                force_logout: true,
                session_version: nextSessionVersion
            });
            await db.ref(`users/${username}/session`).update({ active: false, session_id: null });
            await pushCommand(username, 'RESTORE_ACCOUNT', '');
            await auditLog(req.adminUser, 'RESTORE', username, u.device?.device_id || '', 'Legacy unblock', 'SUCCESS');
            return res.json({ success: true, message: `User ${username} restored (legacy block=false)` });
        }
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/admin/notify', verifyAdmin, checkFirebase, async (req, res) => {
    const username = req.body.username || req.body.user;
    const message = req.body.message;
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    try {
        await pushCommand(username, 'SHOW_MESSAGE', message || '');
        await tryFcm(username, { command: 'SHOW_MESSAGE', message: message || '' });
        await auditLog(req.adminUser, 'SEND_MESSAGE', username, '', message || '', 'SUCCESS');
        res.json({ success: true, message: "Alert sent" });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/admin/send-command', verifyAdmin, checkFirebase, async (req, res) => {
    const username = req.body.username || req.body.user;
    const type = req.body.type;
    const payload = req.body.payload;
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid username" });
    const allowed = ['LOGOUT_NOW','SUSPEND_ACCOUNT','RESTORE_ACCOUNT','SHOW_MESSAGE','REFRESH_SESSION'];
    if (!allowed.includes(type)) return res.status(400).json({ success: false, message: "Unknown command type" });
    try {
        await pushCommand(username, type, payload || '');
        await tryFcm(username, { command: type, payload: payload || '' });
        await auditLog(req.adminUser, 'SEND_COMMAND', username, '', `${type}:${payload || ''}`, 'SUCCESS');
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// ============================================================
// AUDIT LOG ENDPOINT
// ============================================================
app.get('/api/audit-log', verifyAdmin, checkFirebase, async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
        const snap = await db.ref('audit_log').orderByChild('timestamp').limitToLast(limit).once('value');
        const list = [];
        snap.forEach(cs => { list.push({ id: cs.key, ...cs.val() }); });
        list.reverse();
        res.json({ success: true, data: list });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// ============================================================
// APP-FACING ENDPOINTS (called by Android app)
// ============================================================
app.post('/api/auth/login', checkFirebase, async (req, res) => {
    const username = req.body.username || req.body.user;
    const password = req.body.password || req.body.pass;
    const device = req.body.device || req.body.deviceInfo;
    
    if (!isValidUsername(username) || !isValidPassword(password)) {
        return res.status(400).json({ success: false, message: "Invalid input" });
    }
    try {
        let user = await getUser(username);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });
        user = await migrateLegacyUser(username, user);

        // Verify password (prefer hash, fall back to legacy plaintext)
        let pwOk = false;
        if (user.password_hash) {
            try { pwOk = await bcrypt.compare(password, user.password_hash); } catch (_) { pwOk = false; }
        }
        if (!pwOk && user.password === password) pwOk = true; // legacy

        if (!pwOk) return res.status(401).json({ success: false, message: "Invalid credentials" });

        const status = (user.status || 'ACTIVE').toUpperCase();
        if (status === 'SUSPENDED') {
            return res.json({
                success: true,
                status: 'SUSPENDED',
                suspension_reason: user.suspension_reason || '',
                session_id: null
            });
        }
        if (status === 'DISABLED') return res.json({ success: true, status: 'DISABLED', session_id: null });
        if (status === 'REVOKED') return res.json({ success: true, status: 'REVOKED', session_id: null });
        if (status !== 'ACTIVE') return res.status(403).json({ success: false, message: "Account not active" });

        // Device binding check
        const deviceId = device?.device_id;
        if (user.device_binding_enabled && user.device && user.device.device_id && deviceId &&
            user.device.device_id !== deviceId) {
            await auditLog(username, 'DEVICE_MISMATCH', username, deviceId, `Expected ${user.device.device_id}`, 'FAILED');
            return res.status(403).json({
                success: false,
                message: "Account is bound to another device. Contact admin to unbind.",
                code: 'DEVICE_MISMATCH'
            });
        }

        // Issue new session
        const sessionId = crypto.randomBytes(24).toString('hex');
        const now = Date.now();
        const nextSessionVersion = (user.session_version || 0) + 1;
        const sessionObj = {
            session_id: sessionId,
            created_at: now,
            last_verified_at: now,
            session_version: nextSessionVersion,
            device_id: deviceId || '',
            active: true
        };
        const deviceObj = {
            ...(device || {}),
            session_id: sessionId,
            online: true,
            last_seen: now,
            first_seen: user.device?.first_seen || now,   // preserve existing first_seen
            fcm_token: device?.fcm_token || user.device?.fcm_token || ''
        };
        await db.ref(`users/${username}`).update({
            session_version: nextSessionVersion,
            force_logout: false,
            is_blocked: false,
            fcm_token: device?.fcm_token || user.fcm_token || ''
        });
        await db.ref(`users/${username}/session`).set(sessionObj);
        await db.ref(`users/${username}/device`).set(deviceObj);

        await auditLog(username, 'USER_LOGIN', username, deviceId || '', '', 'SUCCESS');
        res.json({
            success: true,
            status: 'ACTIVE',
            session_id: sessionId,
            session_version: nextSessionVersion,
            device_id: deviceId
        });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/session/validate', checkFirebase, async (req, res) => {
    const username = req.body.username || req.body.user;
    const session_id = req.body.session_id || req.body.sessionId;
    const device_id = req.body.device_id || req.body.deviceId;
    
    if (!isValidUsername(username) || !session_id) {
        return res.status(400).json({ success: false, message: "Invalid input" });
    }
    try {
        let user = await getUser(username);
        if (!user) return res.json({ success: true, status: 'REVOKED', session_valid: false, device_valid: false });
        user = await migrateLegacyUser(username, user);
        const status = (user.status || 'ACTIVE').toUpperCase();

        // Legacy is_blocked=true should also read as SUSPENDED
        const effectiveStatus = (user.is_blocked && status === 'ACTIVE') ? 'SUSPENDED' : status;

        const session = user.session || {};
        const sessionValid = !!session.active
            && session.session_id === session_id
            && (session.session_version || 0) === (user.session_version || 0);
        const deviceValid = !user.device_binding_enabled
            || !user.device
            || !user.device.device_id
            || user.device.device_id === device_id;

        // Update last_verified_at
        if (sessionValid) {
            await db.ref(`users/${username}/session/last_verified_at`).set(Date.now());
        }

        const response = {
            success: true,
            status: effectiveStatus,
            session_valid: sessionValid,
            device_valid: deviceValid,
            suspension_reason: user.suspension_reason || ''
        };
        if (effectiveStatus !== 'ACTIVE' || !sessionValid) {
            response.session_id = null;
        }
        res.json(response);
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/device/heartbeat', checkFirebase, async (req, res) => {
    const username = req.body.username || req.body.user;
    const session_id = req.body.session_id || req.body.sessionId;
    const device_id = req.body.device_id || req.body.deviceId;
    const online = req.body.online;
    
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid input" });
    try {
        const now = Date.now();
        const isOnline = online !== false; // default true
        await db.ref(`users/${username}/device`).update({
            last_seen: now,
            online: isOnline
        });
        if (session_id) {
            await db.ref(`users/${username}/session/last_verified_at`).set(now);
        }
        res.json({ success: true, time: now });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/device/register', checkFirebase, async (req, res) => {
    const username = req.body.username || req.body.user;
    const session_id = req.body.session_id || req.body.sessionId;
    const device = req.body.device || req.body.deviceInfo;
    
    if (!isValidUsername(username) || !device) return res.status(400).json({ success: false, message: "Invalid input" });
    try {
        const existing = await getUser(username);
        const now = Date.now();
        const merged = {
            ...(device || {}),
            session_id: session_id || (existing?.session?.session_id || ''),
            online: true,
            last_seen: now,
            first_seen: existing?.device?.first_seen || now
        };
        await db.ref(`users/${username}/device`).update(merged);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/commands/pending', checkFirebase, async (req, res) => {
    const username = req.query.username || req.query.user;
    const session_id = req.query.session_id || req.query.sessionId;
    
    if (!isValidUsername(username)) return res.status(400).json({ success: false, message: "Invalid input" });
    try {
        const snap = await db.ref(`users/${username}/commands`).orderByChild('delivered').equalTo(false).once('value');
        const commands = [];
        const updates = {};
        snap.forEach(cs => {
            const v = cs.val();
            commands.push({ id: cs.key, ...v });
            updates[`${cs.key}/delivered`] = true;
        });
        if (commands.length > 0) {
            await db.ref(`users/${username}/commands`).update(updates);
        }
        res.json({ success: true, commands });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// ============================================================
// HELPERS: pushCommand, tryFcm
// ============================================================
async function pushCommand(username, type, payload) {
    try {
        await db.ref(`users/${username}/commands`).push({
            type,
            payload: payload || '',
            timestamp: Date.now(),
            delivered: false
        });
    } catch (e) { console.error('[pushCommand]', e.message); }
}

async function tryFcm(username, data) {
    if (!messaging) return;
    try {
        const user = await getUser(username);
        const token = user?.fcm_token || user?.device?.fcm_token;
        if (token) {
            await messaging.send({ token, data });
        }
    } catch (e) {
        // FCM failure is non-fatal; polling channel will deliver
        console.warn('[tryFcm] failed (non-fatal):', e.message);
    }
}

// ============================================================
// BOOT
// ============================================================
const PORT = process.env.PORT || 4004;
app.listen(PORT, () => {
    console.log(`[C2 Master Node] Secure panel running at port ${PORT}`);
});
