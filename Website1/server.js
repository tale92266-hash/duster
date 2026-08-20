const express = require('express');
const path = require('path');

const app = express();

// Accept dynamic port from Master Control Plane or fallback to 4001
const PORT = process.env.PORT || 4001;
const SITE_NAME = process.env.SITE_NAME || 'Alpha Store';

// Middleware to parse JSON
app.use(express.json());

// Serve the static frontend files securely
app.use(express.static(path.join(__dirname, 'public')));

// Independent Backend API for Website 1
app.get('/api/products', (req, res) => {
    // In a real scenario, this would come from a database
    const products = [
        { id: 101, name: 'Premium Wireless Headphones', price: 299.99, category: 'Audio' },
        { id: 102, name: 'Mechanical Gaming Keyboard', price: 149.50, category: 'Accessories' },
        { id: 103, name: 'Ultra HD 4K Monitor', price: 499.00, category: 'Displays' },
        { id: 104, name: 'Ergonomic Office Chair', price: 350.00, category: 'Furniture' },
        { id: 105, name: 'USB-C Multiport Hub', price: 45.99, category: 'Accessories' },
        { id: 106, name: 'Smart Home Speaker', price: 89.99, category: 'Audio' }
    ];
    
    res.json({
        success: true,
        site: SITE_NAME,
        data: products
    });
});

// Health check endpoint for Master Server monitoring
app.get('/health', (req, res) => {
    res.json({ status: 'ok', server: SITE_NAME, port: PORT });
});

// Start the server
app.listen(PORT, () => {
    console.log(`[${SITE_NAME}] Sub-server actively running on port ${PORT}`);
});
