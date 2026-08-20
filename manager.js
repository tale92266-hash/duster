const serversData = require('./database.json');

// Get all managed websites/servers
const getWebsites = (req, res) => {
    try {
        // Map data to expected frontend structure
        const websites = serversData.map(srv => ({
            id: srv.id,
            name: srv.name,
            url: srv.url,
            status: srv.status
        }));
        
        res.json({ success: true, websites });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Failed to retrieve server data.' });
    }
};

module.exports = { getWebsites };
