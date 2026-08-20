require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { spawn } = require('child_process');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const activeServers = new Map(); 
const installingServers = new Set(); 

// ==========================================
// 0. LIVE LOGGING SYSTEM (ISOLATED & PRO TERMINAL)
// ==========================================
const serverLogs = { master: [] };
const MAX_LOGS = 1500; 

const stripAnsi = (str) => str.replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '');

const addLog = (type, message, serverId = 'master') => {
    if (!serverLogs[serverId]) {
        serverLogs[serverId] = [];
    }

    const timestamp = new Date().toLocaleTimeString();
    let msgStr = (message || '').toString();
    
    msgStr = stripAnsi(msgStr).trim();
    if (!msgStr) return;
    
    const lines = msgStr.split(/\r?\n/);
    lines.forEach(line => {
        const cleanLine = line.trim();
        if (cleanLine) {
            let actualType = type;
            if (cleanLine.includes('ERR!')) actualType = 'ERROR';
            
            serverLogs[serverId].push({ timestamp, type: actualType, message: cleanLine });
        }
    });
    
    if (serverLogs[serverId].length > MAX_LOGS) serverLogs[serverId].splice(0, serverLogs[serverId].length - MAX_LOGS);
    
    const consolePrefix = serverId === 'master' ? '' : `[${serverId}] `;
    if (type === 'ERROR') console.error(`[${timestamp}] ${consolePrefix}${msgStr}`);
    else console.log(`[${timestamp}] ${consolePrefix}${msgStr}`);
};

// ==========================================
// 1. GLOBAL SECURITY MIDDLEWARES
// ==========================================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"], 
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
        }
    }
}));

// ==========================================
// 2. REVERSE PROXY FOR CLOUD DEPLOYMENT
// ==========================================
try {
    const rawData = fs.readFileSync(path.join(__dirname, 'database.json'), 'utf8');
    const serversData = JSON.parse(rawData);

    serversData.forEach(server => {
        if (server.url && server.url.startsWith('/')) {
            app.use(server.url, (req, res, next) => {
                if (req.originalUrl === server.url) {
                    return res.redirect(301, server.url + '/');
                }
                next();
            });

            app.use(server.url, createProxyMiddleware({
                target: `http://localhost:${server.port}`,
                changeOrigin: true,
                ws: true,
                pathRewrite: { [`^${server.url}`]: '' },
                onError: (err, req, res) => {
                    addLog('ERROR', `[Proxy Error] Failed to reach ${server.name} on port ${server.port}`, server.id);
                    if (!res.headersSent) {
                        res.status(502).send(`<h2 style="font-family:sans-serif; text-align:center; margin-top:50px;">502 Bad Gateway: ${server.name} is offline or booting.</h2>`);
                    }
                }
            }));
            addLog('INFO', `[Reverse Proxy] Route ${server.url} configured to -> localhost:${server.port}`, server.id);
        }
    });
} catch (err) {
    addLog('ERROR', "[Reverse Proxy Error] Failed to configure proxies from database.json");
}

// ==========================================
// 3. PARSERS & RATE LIMITING (FIXED FOR PROXY)
// ==========================================
// 🔥 FIX: sirf un routes ke liye JSON parse karo jo proxied nahi hain
// Taaki proxy ke andar jaane wali request ka body empty na ho.
app.use((req, res, next) => {
    const proxiedRoutes = ['/site1', '/site2', '/site3', '/smartdialer'];
    if (proxiedRoutes.some(route => req.path.startsWith(route))) {
        return next(); // Skip JSON parsing for sub-servers
    }
    express.json({ limit: '10kb' })(req, res, next);
});

app.use(cookieParser());

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many login attempts. Locked for 15 minutes.' }
});

app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 4. AUTHENTICATION LOGIC
// ==========================================
const verifyToken = (req, res, next) => {
    const token = req.cookies.nexus_auth;
    if (!token) return res.status(401).json({ success: false, message: 'Unauthorized. No token provided.' });
    
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (error) {
        res.clearCookie('nexus_auth');
        return res.status(401).json({ success: false, message: 'Invalid or expired session.' });
    }
};

const secureCompare = (input, stored) => {
    try {
        const inputBuffer = Buffer.from(input, 'utf8');
        const storedBuffer = Buffer.from(stored, 'utf8');
        if (inputBuffer.length !== storedBuffer.length) return false;
        return crypto.timingSafeEqual(inputBuffer, storedBuffer);
    } catch { return false; }
};

app.post('/api/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: 'Credentials missing.' });

    if (secureCompare(username, process.env.ADMIN_USERNAME) && secureCompare(password, process.env.ADMIN_PASSWORD)) {
        const token = jwt.sign({ username, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '2h' });
        res.cookie('nexus_auth', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 2 * 60 * 60 * 1000 
        });
        addLog('INFO', `Admin login successful for user: ${username}`);
        return res.json({ success: true, message: 'Authentication successful.' });
    }
    addLog('ERROR', `Failed login attempt for user: ${username}`);
    return res.status(401).json({ success: false, message: 'Invalid credentials.' });
});

app.get('/api/check-auth', verifyToken, (req, res) => res.json({ success: true, user: req.user.username }));
app.post('/api/logout', verifyToken, (req, res) => {
    res.clearCookie('nexus_auth');
    addLog('INFO', `Admin securely logged out.`);
    res.json({ success: true, message: 'Logged out securely.' });
});

// ==========================================
// 5. DEPENDENCY CHECKER & SYMLINKER
// ==========================================
const ensureSymlink = (targetDir) => {
    const rootModules = path.join(__dirname, 'node_modules');
    const targetModules = path.join(targetDir, 'node_modules');
    
    if (!fs.existsSync(rootModules)) {
        fs.mkdirSync(rootModules, { recursive: true });
    }

    if (fs.existsSync(targetModules)) {
        try {
            const stat = fs.lstatSync(targetModules);
            if (stat.isSymbolicLink()) return true; 
            fs.rmSync(targetModules, { recursive: true, force: true });
        } catch (err) {
            addLog('ERROR', `Failed to clean target node_modules for symlink: ${err.message}`);
            return false;
        }
    }

    try {
        fs.symlinkSync(rootModules, targetModules, 'junction'); 
        addLog('INFO', `Symlink mapped: ${path.basename(targetDir)}/node_modules -> ROOT`, 'master');
        return true;
    } catch (err) {
        addLog('ERROR', `Failed to create symlink at ${targetModules}: ${err.message}`);
        return false;
    }
};

const checkDependencies = (targetDir) => {
    const packageJsonPath = path.join(targetDir, 'package.json');
    if (!fs.existsSync(packageJsonPath)) return false; 
    
    try {
        const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        const deps = Object.keys(pkg.dependencies || {});
        
        for (const dep of deps) {
            if (!fs.existsSync(path.join(__dirname, 'node_modules', dep))) {
                return true; 
            }
        }
    } catch (e) {
        return false;
    }
    return false; 
};

// ==========================================
// 6. SERVER MANAGEMENT & LOG API
// ==========================================
app.get('/api/websites', verifyToken, (req, res) => {
    try {
        const rawData = fs.readFileSync(path.join(__dirname, 'database.json'), 'utf8');
        const serversData = JSON.parse(rawData);
        
        const websites = serversData.map(srv => {
            const targetDir = path.resolve(__dirname, srv.directory);
            const isInstalling = installingServers.has(srv.id);
            const needsInstall = checkDependencies(targetDir);
            
            return {
                id: srv.id,
                name: srv.name,
                url: srv.url,
                port: srv.port,
                status: srv.status,
                isInstalling: isInstalling,
                needsInstall: needsInstall && !isInstalling, 
                isRunning: activeServers.has(srv.id)
            };
        });
        
        res.json({ success: true, websites });
    } catch (error) {
        addLog('ERROR', `Failed to retrieve server data: ${error.message}`);
        res.status(500).json({ success: false, message: 'Failed to retrieve server data.' });
    }
});

app.get('/api/logs', verifyToken, (req, res) => {
    const id = req.query.id || 'master';
    res.json({ success: true, logs: serverLogs[id] || [] });
});

// NON-BLOCKING Centralized Background Install Trigger
app.post('/api/action/install', verifyToken, (req, res) => {
    const { id } = req.body;
    
    try {
        const rawData = fs.readFileSync(path.join(__dirname, 'database.json'), 'utf8');
        const serversData = JSON.parse(rawData);
        const server = serversData.find(s => s.id === id);

        if (!server) return res.status(404).json({ success: false, message: 'Server not found.' });
        if (installingServers.has(id)) return res.status(400).json({ success: false, message: 'Installation already in progress.' });

        const targetDir = path.resolve(__dirname, server.directory);
        
        installingServers.add(id);
        addLog('INFO', `[Central Manager] Preparing centralized installation for ${server.name}...`, server.id);
        
        ensureSymlink(targetDir);

        const pkgPath = path.join(targetDir, 'package.json');
        let depsToInstall = [];
        if (fs.existsSync(pkgPath)) {
            try {
                const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
                const deps = pkg.dependencies || {};
                for (const [dep, version] of Object.entries(deps)) {
                    depsToInstall.push(`${dep}@${version}`);
                }
            } catch(e) {}
        }

        if (depsToInstall.length === 0) {
            installingServers.delete(id);
            addLog('INFO', `[Central Manager] No dependencies required. Booting server...`, server.id);
            if (server.status.toLowerCase() === 'online') startSubServer(server);
            return res.json({ success: true, message: 'No dependencies needed. Server booting.' });
        }

        res.json({ success: true, message: 'Centralized installation started. View Live Logs.' });

        addLog('INFO', `[Central Manager] Routing NPM install to ROOT folder to save storage...`, server.id);

        const npmCmd = /^win/.test(process.platform) ? 'npm.cmd' : 'npm';
        const installArgs = ['install', ...depsToInstall, '--loglevel=info', '--no-progress', '--no-audit', '--no-fund'];
        
        const child = spawn(npmCmd, installArgs, { 
            cwd: __dirname, 
            shell: true
        });

        child.stdout.on('data', data => addLog('INFO', data, server.id));
        child.stderr.on('data', data => addLog('INFO', data, server.id));

        child.on('close', (code) => {
            installingServers.delete(id); 
            if (code === 0) {
                addLog('INFO', `[Central Manager] Global Installation finished successfully for ${server.name}.`, server.id);
                if (server.status.toLowerCase() === 'online') {
                    startSubServer(server);
                }
            } else {
                addLog('ERROR', `[Central Manager] Global Installation failed with exit code ${code}`, server.id);
            }
        });
        
        child.on('error', (error) => {
            installingServers.delete(id);
            addLog('ERROR', `[Central Manager] Spawn error: ${error.message}`, server.id);
        });

    } catch (error) {
        installingServers.delete(id);
        addLog('ERROR', `[Central Manager] Internal error: ${error.message}`);
        if (!res.headersSent) res.status(500).json({ success: false, message: 'Internal server error.' });
    }
});

// NON-BLOCKING Background Restart Trigger
app.post('/api/action/restart', verifyToken, (req, res) => {
    const { id } = req.body;
    
    try {
        const rawData = fs.readFileSync(path.join(__dirname, 'database.json'), 'utf8');
        const serversData = JSON.parse(rawData);
        const server = serversData.find(s => s.id === id);

        if (!server) return res.status(404).json({ success: false, message: 'Server not found.' });
        if (installingServers.has(id)) return res.status(400).json({ success: false, message: 'Cannot restart during installation.' });
        if (server.status.toLowerCase() !== 'online') return res.status(400).json({ success: false, message: 'Cannot restart an offline server.' });

        addLog('INFO', `[Process Manager] Manual restart triggered for ${server.name}...`, server.id);
        startSubServer(server);
        
        res.json({ success: true, message: `Restarting ${server.name}. View Live Logs for details.` });
    } catch (error) {
        addLog('ERROR', `[Restart Error] Internal error: ${error.message}`);
        if (!res.headersSent) res.status(500).json({ success: false, message: 'Internal server error.' });
    }
});

// ==========================================
// 7. CHILD PROCESS MANAGER
// ==========================================
const bootProcess = (server, targetDir) => {
    addLog('INFO', `[Process Manager] Booting ${server.name} on PORT ${server.port}...`, server.id);
    const child = spawn('node', ['server.js'], {
        cwd: targetDir,
        env: { ...process.env, PORT: server.port, SITE_NAME: server.name } 
    });

    activeServers.set(server.id, child);

    child.stdout.on('data', data => addLog('INFO', `[${server.name}] ${data}`, server.id));
    child.stderr.on('data', data => addLog('ERROR', `[${server.name} ERROR] ${data}`, server.id));
    
    child.on('close', code => {
        addLog('ERROR', `[Process Manager] ${server.name} exited with code ${code}`, server.id);
        activeServers.delete(server.id);
    });
};

const startSubServer = (server) => {
    const targetDir = path.resolve(__dirname, server.directory);
    const targetScript = path.join(targetDir, 'server.js'); 

    if (!fs.existsSync(targetScript)) {
        addLog('ERROR', `[Process Manager] Warning: Could not find server.js in ${server.directory}.`, server.id);
        return;
    }

    if (activeServers.has(server.id)) {
        addLog('INFO', `[Process Manager] Restarting ${server.name}... Waiting for port release...`, server.id);
        const oldProcess = activeServers.get(server.id);
        oldProcess.kill('SIGKILL');
        activeServers.delete(server.id);
        
        setTimeout(() => {
            bootProcess(server, targetDir);
        }, 1500);
    } else {
        bootProcess(server, targetDir);
    }
};

const autoStartSubServers = () => {
    try {
        const rawData = fs.readFileSync(path.join(__dirname, 'database.json'), 'utf8');
        const serversData = JSON.parse(rawData);

        addLog('INFO', `[Process Manager] Initializing sub-servers...`);

        serversData.forEach(server => {
            if (server.status.toLowerCase() === 'online') {
                const targetDir = path.resolve(__dirname, server.directory);
                
                ensureSymlink(targetDir);

                if (checkDependencies(targetDir)) {
                    addLog('ERROR', `[Process Manager] ⚠️ ${server.name} requires npm install. Waiting for manual approval.`, server.id);
                } else {
                    startSubServer(server);
                }
            }
        });
    } catch (error) {
        addLog('ERROR', `[Process Manager] Failed to parse database.json for auto-start.`);
    }
};

// ==========================================
// 8. SERVER BOOTSTRAP
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    addLog('INFO', `[Master Server] Secured backend running on http://localhost:${PORT}`);
    autoStartSubServers(); 
});