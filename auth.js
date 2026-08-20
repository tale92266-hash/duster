const jwt = require('jsonwebtoken');

// Middleware to verify JWT cookie
const verifyToken = (req, res, next) => {
    const token = req.cookies.nexus_auth;
    if (!token) {
        return res.status(401).json({ success: false, message: 'Unauthorized. No token provided.' });
    }
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (error) {
        res.clearCookie('nexus_auth');
        return res.status(401).json({ success: false, message: 'Invalid or expired session.' });
    }
};

// Login Route Handler
const loginHandler = (req, res) => {
    const { username, password } = req.body;

    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
        const token = jwt.sign({ username, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '2h' });
        
        res.cookie('nexus_auth', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 2 * 60 * 60 * 1000 // 2 hours
        });
        
        return res.json({ success: true, message: 'Authentication successful.' });
    }
    
    return res.status(401).json({ success: false, message: 'Invalid credentials.' });
};

// Check Auth Status Handler
const checkAuthHandler = (req, res) => {
    res.json({ success: true, user: req.user.username });
};

// Logout Handler
const logoutHandler = (req, res) => {
    res.clearCookie('nexus_auth');
    res.json({ success: true, message: 'Logged out securely.' });
};

module.exports = { verifyToken, loginHandler, checkAuthHandler, logoutHandler };
