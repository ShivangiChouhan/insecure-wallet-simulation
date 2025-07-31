// Insecure Wallet - Client-Side JavaScript
// This file contains intentional security vulnerabilities for educational purposes

// Global variables
let currentUser = null;
let currentUserId = null;
let isLoggedIn = false;

// Simulated backend data (VULNERABILITY: Exposed data)
const MOCK_USERS = [
    { id: 1, username: 'alice', password: 'password123', balance: 1000, role: 'user' },
    { id: 2, username: 'bob', password: 'password123', balance: 500, role: 'user' },
    { id: 3, username: 'admin', password: 'admin123', balance: 10000, role: 'admin' }
];

// Weak JWT simulation (VULNERABILITY: Predictable tokens)
function generateToken(user) {
    const timestamp = Date.now();
    const payload = btoa(JSON.stringify({
        id: user.id,
        username: user.username,
        role: user.role,
        exp: timestamp + (24 * 60 * 60 * 1000) // 24 hours
    }));
    
    // VULNERABILITY: Weak signature
    const signature = btoa(`${user.id}_${user.username}_secret`);
    return `${payload}.${signature}`;
}

// Token validation (VULNERABILITY: Poor validation)
function validateToken(token) {
    if (!token) return null;
    
    try {
        const [payload] = token.split('.');
        const data = JSON.parse(atob(payload));
        
        // VULNERABILITY: No expiration check, weak validation
        return data;
    } catch (error) {
        return null;
    }
}

// Mock API endpoints simulation
const mockAPI = {
    // Login endpoint (VULNERABILITY: Client-side authentication)
    login: async (username, password) => {
        await new Promise(resolve => setTimeout(resolve, 500)); // Simulate network delay
        
        const user = MOCK_USERS.find(u => u.username === username);
        
        if (!user) {
            return { success: false, error: 'User not found' };
        }
        
        // VULNERABILITY: Plain text password comparison
        if (user.password !== password) {
            return { success: false, error: 'Invalid password' };
        }
        
        const token = generateToken(user);
        
        return {
            success: true,
            token: token,
            user: { id: user.id, username: user.username, role: user.role }
        };
    },
    
    // Get wallet data (VULNERABILITY: IDOR)
    getWallet: async (userId, token) => {
        await new Promise(resolve => setTimeout(resolve, 300));
        
        const tokenData = validateToken(token);
        if (!tokenData) {
            return { success: false, error: 'Invalid token' };
        }
        
        // VULNERABILITY: No authorization check - any valid token can access any wallet
        const user = MOCK_USERS.find(u => u.id == userId);
        if (!user) {
            return { success: false, error: 'User not found' };
        }
        
        return {
            success: true,
            id: user.id,
            username: user.username,
            balance: user.balance,
            role: user.role
        };
    },
    
    // Perform transaction (VULNERABILITY: CSRF, IDOR, Missing authorization)
    transaction: async (userId, type, amount, token) => {
        await new Promise(resolve => setTimeout(resolve, 400));
        
        const tokenData = validateToken(token);
        if (!tokenData) {
            return { success: false, error: 'Invalid token' };
        }
        
        const user = MOCK_USERS.find(u => u.id == userId);
        if (!user) {
            return { success: false, error: 'User not found' };
        }
        
        const parsedAmount = parseFloat(amount);
        if (isNaN(parsedAmount) || parsedAmount <= 0) {
            return { success: false, error: 'Invalid amount' };
        }
        
        if (type === 'deposit') {
            user.balance += parsedAmount;
        } else if (type === 'withdraw') {
            if (user.balance < parsedAmount) {
                return { success: false, error: 'Insufficient funds' };
            }
            user.balance -= parsedAmount;
        } else {
            return { success: false, error: 'Invalid transaction type' };
        }
        
        return {
            success: true,
            newBalance: user.balance,
            message: `${type} of $${parsedAmount.toFixed(2)} successful`
        };
    },
    
    // Get all users (VULNERABILITY: Information disclosure)
    getAllUsers: async (token) => {
        await new Promise(resolve => setTimeout(resolve, 200));
        
        const tokenData = validateToken(token);
        if (!tokenData) {
            return { success: false, error: 'Invalid token' };
        }
        
        // VULNERABILITY: Any authenticated user can see all users
        return {
            success: true,
            users: MOCK_USERS.map(u => ({
                id: u.id,
                username: u.username,
                balance: u.balance,
                role: u.role
            }))
        };
    }
};

// Utility functions
function showMessage(message, type = 'info', duration = 5000) {
    const messagesContainer = document.getElementById('messages') || createMessagesContainer();
    
    const messageElement = document.createElement('div');
    messageElement.className = `message ${type}`;
    messageElement.textContent = message;
    
    messagesContainer.appendChild(messageElement);
    
    // Auto-remove message
    setTimeout(() => {
        if (messageElement.parentNode) {
            messageElement.parentNode.removeChild(messageElement);
        }
    }, duration);
    
    // Add click to dismiss
    messageElement.addEventListener('click', () => {
        if (messageElement.parentNode) {
            messageElement.parentNode.removeChild(messageElement);
        }
    });
}

function createMessagesContainer() {
    const container = document.createElement('div');
    container.id = 'messages';
    container.className = 'messages';
    document.body.appendChild(container);
    return container;
}

function getStoredToken() {
    return localStorage.getItem('token');
}

function getStoredUser() {
    const user = localStorage.getItem('user');
    return user ? JSON.parse(user) : null;
}

function clearStorage() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
}

function redirectToLogin() {
    window.location.href = 'loginpage.html';
}

function redirectToWallet(userId) {
    window.location.href = `wallet.html?userId=${userId}`;
}

// Page-specific initialization
function initializePage() {
    const path = window.location.pathname;
    const filename = path.split('/').pop() || 'index.html';
    
    switch (filename) {
        case 'loginpage.html':
        case 'login.html':
            initializeLoginPage();
            break;
        case 'wallet.html':
            initializeWalletPage();
            break;
        case 'index.html':
        default:
            initializeHomePage();
            break;
    }
}

// Home page initialization
function initializeHomePage() {
    console.log('Home page initialized');
    
    // Check if user is already logged in
    const token = getStoredToken();
    const user = getStoredUser();
    
    if (token && user) {
        showMessage(`Welcome back, ${user.username}! You can access your wallet.`, 'info');
    }
}

// Login page initialization
function initializeLoginPage() {
    console.log('Login page initialized');
    
    // Check if already logged in
    const token = getStoredToken();
    const user = getStoredUser();
    
    if (token && user) {
        showMessage('You are already logged in. Redirecting...', 'info');
        setTimeout(() => redirectToWallet(user.id), 1500);
        return;
    }
    
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    // Quick login buttons
    setupQuickLoginButtons();
}

// Wallet page initialization
function initializeWalletPage() {
    console.log('Wallet page initialized');
    
    const token = getStoredToken();
    const user = getStoredUser();
    
    if (!token) {
        showMessage('Please log in to access your wallet', 'error');
        setTimeout(redirectToLogin, 2000);
        return;
    }
    
    // Get userId from URL (VULNERABILITY: Relying on client-side parameters)
    const urlParams = new URLSearchParams(window.location.search);
    currentUserId = urlParams.get('userId') || (user ? user.id : null);
    
    if (!currentUserId) {
        showMessage('Invalid wallet access', 'error');
        setTimeout(redirectToLogin, 2000);
        return;
    }
    
    currentUser = user;
    setupWalletInterface();
    loadWalletData();
}

// Login handling
async function handleLogin(event) {
    event.preventDefault();
    
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    
    const errorDiv = document.getElementById('loginError');
    const successDiv = document.getElementById('loginSuccess');
    
    if (errorDiv) errorDiv.style.display = 'none';
    if (successDiv) successDiv.style.display = 'none';
    
    if (!username || !password) {
        showError('Please enter both username and password');
        return;
    }
    
    try {
        showMessage('Logging in...', 'info', 2000);
        
        const result = await mockAPI.login(username, password);
        
        if (result.success) {
            // Store credentials (VULNERABILITY: Client-side storage)
            localStorage.setItem('token', result.token);
            localStorage.setItem('user', JSON.stringify(result.user));
            
            if (successDiv) {
                successDiv.textContent = 'Login successful! Redirecting...';
                successDiv.style.display = 'block';
            }
            
            showMessage('Login successful!', 'success');
            
            setTimeout(() => {
                redirectToWallet(result.user.id);
            }, 1500);
            
        } else {
            if (errorDiv) {
                errorDiv.textContent = result.error;
                errorDiv.style.display = 'block';
            }
            showMessage('Login failed: ' + result.error, 'error');
        }
        
    } catch (error) {
        console.error('Login error:', error);
        showMessage('Network error during login', 'error');
        if (errorDiv) {
            errorDiv.textContent = 'Network error. Please try again.';
            errorDiv.style.display = 'block';
        }
    }
}

function showError(message) {
    const errorDiv = document.getElementById('loginError');
    if (errorDiv) {
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
    }
    showMessage(message, 'error');
}

// Quick login setup
function setupQuickLoginButtons() {
    const quickLoginButtons = document.querySelectorAll('[onclick^="quickLogin"]');
    quickLoginButtons.forEach(button => {
        button.onclick = null; // Remove inline onclick
        
        const onclickAttr = button.getAttribute('onclick');
        const match = onclickAttr.match(/quickLogin\('([^']+)',\s*'([^']+)'\)/);
        
        if (match) {
            const [, username, password] = match;
            button.addEventListener('click', () => quickLogin(username, password));
        }
    });
}

function quickLogin(username, password) {
    const usernameField = document.getElementById('username');
    const passwordField = document.getElementById('password');
    const loginForm = document.getElementById('loginForm');
    
    if (usernameField && passwordField && loginForm) {
        usernameField.value = username;
        passwordField.value = password;
        
        // Trigger form submission
        const submitEvent = new Event('submit', { bubbles: true, cancelable: true });
        loginForm.dispatchEvent(submitEvent);
    }
}

// Wallet interface setup
function setupWalletInterface() {
    // Update user info display
    const userInfoElement = document.getElementById('userInfo');
    if (userInfoElement && currentUser) {
        userInfoElement.textContent = `Welcome, ${currentUser.username} (${currentUser.role})`;
    }
    
    // Setup form handlers
    const depositForm = document.getElementById('depositForm');
    const withdrawForm = document.getElementById('withdrawForm');
    
    if (depositForm) {
        depositForm.addEventListener('submit', (e) => handleTransaction(e, 'deposit'));
    }
    
    if (withdrawForm) {
        withdrawForm.addEventListener('submit', (e) => handleTransaction(e, 'withdraw'));
    }
    
    // Setup vulnerability demo buttons
    setupVulnerabilityDemos();
    
    // Update account ID display
    const accountIdElement = document.getElementById('accountId');
    if (accountIdElement) {
        accountIdElement.textContent = currentUserId;
    }
    
    // Update IDOR URL display
    const idorUrlElement = document.getElementById('idorUrl');
    if (idorUrlElement) {
        idorUrlElement.value = `wallet.html?userId=${currentUserId}`;
    }
}

// Load wallet data
async function loadWalletData(userId = currentUserId) {
    const token = getStoredToken();

    try {
        const response = await fetch(`/api/wallet/${userId}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        const result = await response.json();

        if (response.ok && result.success !== false) {
            // Update balance display
            const balanceElement = document.getElementById('balance');
            if (balanceElement) {
                balanceElement.textContent = result.balance.toFixed(2);
            }
            showMessage(`Loaded wallet for ${result.username} (ID: ${result.id})`, 'info', 3000);
            if (result.id == currentUserId) {
                currentUser = { ...currentUser, balance: result.balance };
            }
        } else {
            showMessage('Error loading wallet: ' + (result.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        console.error('Error loading wallet:', error);
        showMessage('Network error loading wallet data', 'error');
    }
}

// Handle transactions
async function handleTransaction(event, type) {
    event.preventDefault();
    
    const amountInput = document.getElementById(`${type}Amount`);
    const amount = amountInput ? amountInput.value : '';
    
    if (!amount || parseFloat(amount) <= 0) {
        showMessage('Please enter a valid amount', 'error');
        return;
    }
    
    await performTransaction(type, amount, currentUserId);
    
    // Clear form
    if (amountInput) {
        amountInput.value = '';
    }
}

// Perform transaction (VULNERABLE: CSRF, IDOR)
async function performTransaction(type, amount, userId = currentUserId) {
    const token = getStoredToken();
    
    if (!token) {
        showMessage('Please log in first', 'error');
        redirectToLogin();
        return;
    }
    
    try {
        showMessage(`Processing ${type}...`, 'info', 2000);
        
        const result = await mockAPI.transaction(userId, type, amount, token);
        
        if (result.success) {
            // Update balance display
            const balanceElement = document.getElementById('balance');
            if (balanceElement) {
                balanceElement.textContent = result.newBalance.toFixed(2);
            }
            
            showMessage(`${type.charAt(0).toUpperCase() + type.slice(1)} successful! New balance: $${result.newBalance.toFixed(2)}`, 'success');
            
        } else {
            showMessage('Transaction failed: ' + result.error, 'error');
        }
        
    } catch (error) {
        console.error('Transaction error:', error);
        showMessage('Network error during transaction', 'error');
    }
}

// Vulnerability demonstration functions
function setupVulnerabilityDemos() {
    // IDOR test button
    const idorButton = document.querySelector('[onclick="testIDOR()"]');
    if (idorButton) {
        idorButton.onclick = null;
        idorButton.addEventListener('click', testIDOR);
    }
    
    // View all users button
    const viewUsersButton = document.querySelector('[onclick="viewAllUsers()"]');
    if (viewUsersButton) {
        viewUsersButton.onclick = null;
        viewUsersButton.addEventListener('click', viewAllUsers);
    }
    
    // Cross-account attack button
    const attackButton = document.querySelector('[onclick="crossAccountWithdraw()"]');
    if (attackButton) {
        attackButton.onclick = null;
        attackButton.addEventListener('click', crossAccountWithdraw);
    }
    
    // Logout button
    const logoutButton = document.querySelector('[onclick="logout()"]');
    if (logoutButton) {
        logoutButton.onclick = null;
        logoutButton.addEventListener('click', logout);
    }
}

// IDOR vulnerability demonstration
function testIDOR() {
    const newUserId = prompt('Enter user ID to access (try 1, 2, or 3):');
    
    if (newUserId && !isNaN(newUserId)) {
        showMessage(`Attempting IDOR attack on user ${newUserId}...`, 'info');
        setTimeout(() => {
            window.location.href = `wallet.html?userId=${newUserId}`;
        }, 1000);
    } else if (newUserId !== null) {
        showMessage('Please enter a valid user ID', 'error');
    }
}

// View all users (Information disclosure vulnerability)
async function viewAllUsers() {
    const token = getStoredToken();
    
    if (!token) {
        showMessage('Please log in first', 'error');
        return;
    }
    
    try {
        showMessage('Loading all users...', 'info', 2000);
        
        const result = await mockAPI.getAllUsers(token);
        
        if (result.success) {
            const usersContainer = document.getElementById('allUsers');
            if (usersContainer) {
                usersContainer.innerHTML = '<h4>All Users (Information Disclosure Vulnerability):</h4>' + 
                    result.users.map(user => 
                        `<div class="user-item">
                            <div>
                                <strong>ID:</strong> ${user.id} | 
                                <strong>Username:</strong> ${user.username} | 
                                <strong>Balance:</strong> $${user.balance.toFixed(2)} | 
                                <strong>Role:</strong> ${user.role}
                            </div>
                            <button onclick="accessUserWallet(${user.id})" class="btn btn-warning btn-sm">Access Wallet</button>
                        </div>`
                    ).join('');
                
                // Add event listeners for access buttons
                usersContainer.querySelectorAll('[onclick^="accessUserWallet"]').forEach(button => {
                    button.onclick = null;
                    const userId = button.getAttribute('onclick').match(/\d+/)[0];
                    button.addEventListener('click', () => accessUserWallet(userId));
                });
            }
            
            showMessage(`Loaded ${result.users.length} users (Security vulnerability!)`, 'info');
            
        } else {
            showMessage('Error loading users: ' + result.error, 'error');
        }
        
    } catch (error) {
        console.error('Error loading users:', error);
        showMessage('Network error loading users', 'error');
    }
}

// Access another user's wallet
function accessUserWallet(userId) {
    showMessage(`Accessing wallet for user ID ${userId} (IDOR vulnerability)`, 'info');
    currentUserId = userId;
    loadWalletData(userId);
    
    // Update URL
    const newUrl = `wallet.html?userId=${userId}`;
    window.history.pushState({}, '', newUrl);
    
    // Update IDOR URL display
    const idorUrlElement = document.getElementById('idorUrl');
    if (idorUrlElement) {
        idorUrlElement.value = newUrl;
    }
}

// Cross-account attack demonstration
async function crossAccountWithdraw() {
    const targetIdInput = document.getElementById('targetUserId');
    const attackAmountInput = document.getElementById('attackAmount');
    
    const targetId = targetIdInput ? targetIdInput.value : '';
    const amount = attackAmountInput ? attackAmountInput.value : '';
    
    if (!targetId || !amount) {
        showMessage('Please enter target user ID and amount', 'error');
        return;
    }
    
    if (isNaN(targetId) || isNaN(amount) || parseFloat(amount) <= 0) {
        showMessage('Please enter valid numeric values', 'error');
        return;
    }
    
    showMessage(`Attempting cross-account attack on user ${targetId}...`, 'info');
    
    await performTransaction('withdraw', amount, targetId);
    
    // Clear attack form
    if (targetIdInput) targetIdInput.value = '';
    if (attackAmountInput) attackAmountInput.value = '';
}

// Logout function
function logout() {
    showMessage('Logging out...', 'info', 2000);
    
    clearStorage();
    currentUser = null;
    currentUserId = null;
    isLoggedIn = false;
    setTimeout(() => {
        redirectToLogin();
    }, 1500);
}

// Initialize page when DOM is loaded
document.addEventListener('DOMContentLoaded', initializePage);

// Global error handler for unhandled promise rejections
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    showMessage('An unexpected error occurred', 'error');
});

// Global error handler for JavaScript errors
window.addEventListener('error', (event) => {
    console.error('JavaScript error:', event.error);
    showMessage('A JavaScript error occurred', 'error');
});

// Simulate network fetch for mock API calls
async function mockFetch(url, options = {}) {
    const { method = 'GET', headers = {}, body } = options;
    
    // Parse URL and extract endpoint
    const urlParts = url.split('/');
    const endpoint = urlParts[urlParts.length - 1];
    const action = urlParts[urlParts.length - 2];
    
    try {
        // Handle different API endpoints
        if (url.includes('/api/login')) {
            const { username, password } = JSON.parse(body);
            return {
                ok: true,
                json: async () => await mockAPI.login(username, password)
            };
        }
        
        if (url.includes('/api/wallet/') && method === 'GET') {
            const userId = url.match(/\/api\/wallet\/(\d+)/)[1];
            const token = headers.Authorization?.replace('Bearer ', '');
            const result = await mockAPI.getWallet(userId, token);
            
            return {
                ok: result.success,
                json: async () => result.success ? result : { error: result.error }
            };
        }
        
        if (url.includes('/api/wallet/') && method === 'POST') {
            const matches = url.match(/\/api\/wallet\/(\d+)\/(\w+)/);
            if (matches) {
                const [, userId, transactionType] = matches;
                const { amount } = JSON.parse(body);
                const token = headers.Authorization?.replace('Bearer ', '');
                const result = await mockAPI.transaction(userId, transactionType, amount, token);
                
                return {
                    ok: result.success,
                    json: async () => result.success ? result : { error: result.error }
                };
            }
        }
        
        if (url.includes('/api/users')) {
            const token = headers.Authorization?.replace('Bearer ', '');
            const result = await mockAPI.getAllUsers(token);
            
            return {
                ok: result.success,
                json: async () => result.success ? result.users : { error: result.error }
            };
        }
        
        // Default 404 response
        return {
            ok: false,
            json: async () => ({ error: 'Endpoint not found' })
        };
        
    } catch (error) {
        console.error('Mock fetch error:', error);
        return {
            ok: false,
            json: async () => ({ error: 'Server error' })
        };
    }
}

// Override fetch for this demo
const originalFetch = window.fetch;
window.fetch = function(url, options) {
    // Use mock API for our demo endpoints
    if (url.startsWith('/api/')) {
        return mockFetch(url, options);
    }
    
    // Use real fetch for other requests
    return originalFetch.apply(this, arguments);
};

// Additional utility functions for demonstration

// Generate vulnerability report
function generateVulnerabilityReport() {
    const vulnerabilities = [
        {
            name: 'Cross-Site Request Forgery (CSRF)',
            severity: 'High',
            description: 'No CSRF tokens protecting state-changing operations',
            location: 'Transaction endpoints (/api/wallet/{id}/deposit, /api/wallet/{id}/withdraw)',
            impact: 'Attackers can perform unauthorized transactions'
        },
        {
            name: 'Insecure Direct Object Reference (IDOR)',
            severity: 'High', 
            description: 'User ID in URL allows access to other users\' wallets',
            location: 'wallet.html?userId={id}',
            impact: 'Any authenticated user can access any wallet'
        },
        {
            name: 'Broken Authentication',
            severity: 'Medium',
            description: 'Weak JWT implementation with no proper validation',
            location: 'Token generation and validation functions',
            impact: 'Tokens can be easily forged or manipulated'
        },
        {
            name: 'Information Disclosure',
            severity: 'Medium',
            description: 'All users can view complete user list with balances',
            location: '/api/users endpoint',
            impact: 'Sensitive user information exposed to all authenticated users'
        },
        {
            name: 'Client-Side Security Controls',
            severity: 'High',
            description: 'Security logic implemented on client-side',
            location: 'JavaScript authentication and authorization',
            impact: 'Security controls can be bypassed by modifying client code'
        }
    ];
    
    return vulnerabilities;
}

// Demonstration functions for educational purposes
const securityDemo = {
    // Show how tokens can be manipulated
    showTokenStructure: function() {
        const token = getStoredToken();
        if (!token) {
            showMessage('Please log in first to see token structure', 'error');
            return;
        }
        
        const [payload, signature] = token.split('.');
        try {
            const decoded = JSON.parse(atob(payload));
            console.log('Token Structure (VULNERABILITY: Visible structure):');
            console.log('Payload:', decoded);
            console.log('Signature:', signature);
            console.log('Full Token:', token);
            
            showMessage('Token structure logged to console (F12 to view)', 'info');
        } catch (error) {
            showMessage('Error decoding token', 'error');
        }
    },
    
    // Demonstrate CSRF vulnerability
    createCSRFDemo: function() {
        const currentDomain = window.location.origin;
        const csrfHTML = `
<!DOCTYPE html>
<html>
<head><title>CSRF Attack Demo</title></head>
<body>
    <h1>Innocent Looking Page</h1>
    <p>This page contains a hidden CSRF attack!</p>
    
    <!-- Hidden CSRF attack form -->
    <form id="csrfAttack" action="${currentDomain}/api/wallet/1/withdraw" method="POST" style="display:none;">
        <input name="amount" value="100" />
    </form>
    
    <script>
        // Auto-submit the form when page loads
        document.getElementById('csrfAttack').submit();
    </script>
</body>
</html>`;
        
        console.log('CSRF Attack Demo HTML:');
        console.log(csrfHTML);
        showMessage('CSRF demo HTML logged to console', 'info');
    },
    
    // Show all vulnerabilities
    listVulnerabilities: function() {
        const vulns = generateVulnerabilityReport();
        console.log('Security Vulnerabilities Found:');
        vulns.forEach((vuln, index) => {
            console.log(`${index + 1}. ${vuln.name} (${vuln.severity})`);
            console.log(`   Description: ${vuln.description}`);
            console.log(`   Location: ${vuln.location}`);
            console.log(`   Impact: ${vuln.impact}\n`);
        });
        showMessage(`${vulns.length} vulnerabilities logged to console`, 'info');
    }
};

// Make security demo functions available globally for testing
window.securityDemo = securityDemo;

// Development helper functions
const devHelpers = {
    // Reset all user balances
    resetBalances: function() {
        MOCK_USERS.forEach(user => {
            if (user.username === 'alice') user.balance = 1000;
            else if (user.username === 'bob') user.balance = 500;
            else if (user.username === 'admin') user.balance = 10000;
        });
        
        showMessage('All user balances reset to default values', 'info');
        
        // Refresh current wallet display if on wallet page
        if (currentUserId) {
            loadWalletData(currentUserId);
        }
    },
    
    // Show current application state
    showAppState: function() {
        const state = {
            currentUser,
            currentUserId,
            isLoggedIn,
            storedToken: getStoredToken(),
            storedUser: getStoredUser(),
            allUsers: MOCK_USERS,
            currentPage: window.location.pathname
        };
        
        console.log('Current Application State:');
        console.log(JSON.stringify(state, null, 2));
        showMessage('Application state logged to console', 'info');
    },
    
    // Clear all storage and reset state
    clearAll: function() {
        clearStorage();
        currentUser = null;
        currentUserId = null;
        isLoggedIn = false;
        showMessage('All storage cleared and state reset', 'info');
    }
};

// Make dev helpers available globally
window.devHelpers = devHelpers;

// Console welcome message
console.log('%cInsecure Wallet Security Demo', 'color: #ff6b6b; font-size: 20px; font-weight: bold;');
console.log('%cThis application contains intentional security vulnerabilities for educational purposes.', 'color: #ffa726; font-size: 14px;');
console.log('%cAvailable commands:', 'color: #42a5f5; font-size: 14px; font-weight: bold;');
console.log('- securityDemo.showTokenStructure() - View JWT token structure');
console.log('- securityDemo.createCSRFDemo() - Generate CSRF attack demo');
console.log('- securityDemo.listVulnerabilities() - List all vulnerabilities');
console.log('- devHelpers.resetBalances() - Reset all user balances');
console.log('- devHelpers.showAppState() - Show current application state');
console.log('- devHelpers.clearAll() - Clear storage and reset state');
console.log('%cHappy hacking! 🔓', 'color: #66bb6a; font-size: 16px;');
