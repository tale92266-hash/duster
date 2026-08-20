// Wait for DOM to load completely
document.addEventListener('DOMContentLoaded', () => {
    
    // UI Elements
    const productGrid = document.getElementById('productGrid');
    const loader = document.getElementById('loader');

    // Fetch Products from the Independent Sub-Server API
    const fetchProducts = async () => {
        try {
            // FIX: Added dot (.) to make it a relative path. 
            // Now it respects the reverse proxy URL dynamically!
            const response = await fetch('./api/products');
            
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            
            const result = await response.json();
            
            if (result.success && result.data) {
                renderProducts(result.data);
            } else {
                throw new Error('Invalid data format received');
            }
            
        } catch (error) {
            console.error('Failed to fetch products:', error);
            loader.innerHTML = '<p style="color: red;">Failed to load products. Ensure the server is running.</p>';
        }
    };

    // Render Products to the DOM
    const renderProducts = (products) => {
        // Hide loader, show grid
        loader.classList.add('hidden');
        productGrid.classList.remove('hidden');

        // SVG Icon Template for Products
        const getIcon = () => `
            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
                <line x1="8" y1="21" x2="16" y2="21"></line>
                <line x1="12" y1="17" x2="12" y2="21"></line>
            </svg>
        `;

        // Generate HTML for each product
        const html = products.map(product => `
            <div class="product-card">
                <div class="product-icon">
                    ${getIcon()}
                </div>
                <div class="product-category">${product.category}</div>
                <h3 class="product-title">${product.name}</h3>
                <div class="product-footer">
                    <span class="product-price">$${product.price.toFixed(2)}</span>
                    <button class="btn btn-outline" onclick="alert('Added ${product.name} to cart!')">Add to Cart</button>
                </div>
            </div>
        `).join('');

        // Inject into the grid
        productGrid.innerHTML = html;
    };

    // Initialize fetching
    fetchProducts();
});
