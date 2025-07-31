const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'weak_secret_123'; // VULNERABILITY: Weak secret

// Middleware
app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// Mock database (in production, use real database)
const users = [
    {
        id: 1,
        username: 'alice',
        password: '$2a$10$rVjw8/QQc8QyJ8QyJ8QyJ.', // 'password123'
        balance: 1000,
        role: 'user'
    },
    {
        id: 2,
        username: 'bob',
        password: '$2a$10$rVjw8/QQc8QyJ8QyJ8QyJ.', // 'password123'
        balance: 500,
        role: 'user'
    },
    {
        id: 3,
        username: 'admin',
        password: '$2a$10$rVjw8/QQc8QyJ8QyJ8QyJ.', // 'admin123'
        balance: 10000,
        role: 'admin'
    }
];

const transactions = [];

// VULNERABILITY 1: No CSRF protection
// VULNERABILITY 2: Weak authentication
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    // Find user
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // VULNERABILITY: Simple password check (in real app, use bcrypt properly)
    if (password !== 'password123' && !(username === 'admin' && password === 'admin123')) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // VULNERABILITY: Token never expires and uses weak secret
    const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET
        // No expiration time - tokens live forever!
    );
    
    // VULNERABILITY: Token in both cookie and response (token reuse)
    res.cookie('token', token, { httpOnly: false }); // httpOnly: false makes it accessible via JS
    res.json({ 
        success: true, 
        token, // Also sending in response body
        user: { id: user.id, username: user.username, role: user.role, balance: user.balance }
    });
});

// VULNERABILITY 3: IDOR - Insecure Direct Object Reference
app.get('/api/wallet/:userId', (req, res) => {
    const { userId } = req.params;
    const token = req.headers.authorization?.split(' ')[1] || req.cookies.token;
    
    // VULNERABILITY: No proper token validation
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        // VULNERABILITY: Not checking if token user matches requested userId
        jwt.verify(token, JWT_SECRET);
        
        // VULNERABILITY: IDOR - Any authenticated user can access any wallet
        const user = users.find(u => u.id == userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({
            id: user.id,
            username: user.username,
            balance: user.balance,
            role: user.role
        });
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// VULNERABILITY: No CSRF protection on state-changing operations
app.post('/api/wallet/:userId/deposit', (req, res) => {
    const { userId } = req.params;
    const { amount } = req.body;
    const token = req.headers.authorization?.split(' ')[1] || req.cookies.token;
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // VULNERABILITY: Not checking if token user matches userId
        const user = users.find(u => u.id == userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // VULNERABILITY: No input validation
        user.balance += parseFloat(amount);
        
        transactions.push({
            id: transactions.length + 1,
            userId: user.id,
            type: 'deposit',
            amount: parseFloat(amount),
            timestamp: new Date()
        });
        
        res.json({ success: true, newBalance: user.balance });
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.post('/api/wallet/:userId/withdraw', (req, res) => {
    const { userId } = req.params;
    const { amount } = req.body;
    const token = req.headers.authorization?.split(' ')[1] || req.cookies.token;
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // VULNERABILITY: IDOR - any user can withdraw from any account
        const user = users.find(u => u.id == userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (user.balance < amount) {
            return res.status(400).json({ error: 'Insufficient funds' });
        }
        
        user.balance -= parseFloat(amount);
        
        transactions.push({
            id: transactions.length + 1,
            userId: user.id,
            type: 'withdraw',
            amount: parseFloat(amount),
            timestamp: new Date()
        });
        
        res.json({ success: true, newBalance: user.balance });
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// Get all users (admin only - but no proper authorization check)
app.get('/api/users', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies.token;
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // VULNERABILITY: No role-based access control
        // Any authenticated user can see all users
        res.json(users.map(u => ({
            id: u.id,
            username: u.username,
            balance: u.balance,
            role: u.role
        })));
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.listen(PORT, () => {
    console.log(`Insecure Wallet Server running on http://localhost:${PORT}`);
    console.log('\n=== TEST ACCOUNTS ===');
    console.log('Username: alice, Password: password123');
    console.log('Username: bob, Password: password123'); 
    console.log('Username: admin, Password: admin123');
    console.log('=====================\n');
});