require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();

// Add this line to trust proxy headers
app.set('trust proxy', 1); // Trust first proxy (Render.com's load balancer)

const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
// Replace your current CORS setup with this:
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || 'https://anatolyworkout.com',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Add CSP headers middleware
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
    "connect-src 'self' https://mortgage-backend-wl3e.onrender.com; " +
    "script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:"
  );
  next();
});
app.use(bodyParser.json());

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: 'Too many requests from this IP, please try again later'
});
app.use('/api/', apiLimiter);

// In-memory database (replace with real DB in production)
const users = [
    {
        id: 1,
        username: 'admin',
        passwordHash: bcrypt.hashSync('admin123', 10),
        role: 'admin'
    }
];

const SECRET_KEY = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_EXPIRY = '1h';

// Request signature validation middleware
function validateSignature(req, res, next) {
    const { signature, timestamp, nonce } = req.headers;
    
    if (!signature || !timestamp || !nonce) {
        return res.status(401).json({ error: 'Missing authentication headers' });
    }
    
    // Verify timestamp is recent (within 5 minutes)
    if (Math.abs(Date.now() - parseInt(timestamp)) > 300000) {
        return res.status(401).json({ error: 'Expired request' });
    }
    
    // In production, implement proper signing logic
    const expectedSig = crypto.createHmac('sha256', SECRET_KEY)
        .update(`${timestamp}:${nonce}:${JSON.stringify(req.body)}`)
        .digest('hex');
    
    if (signature !== expectedSig) {
        return res.status(401).json({ error: 'Invalid signature' });
    }
    
    next();
}

// JWT Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Admin role check middleware
function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

// API Routes

// Auth endpoints
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    
    const user = users.find(u => u.username === username);
    if (!user || !await bcrypt.compare(password, user.passwordHash)) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        SECRET_KEY,
        { expiresIn: TOKEN_EXPIRY }
    );
    
    res.json({ 
        token,
        user: { username: user.username, role: user.role }
    });
});

app.post('/api/auth/register', (req, res) => {
    const { username, password } = req.body;
    
    if (users.some(u => u.username === username)) {
        return res.status(400).json({ error: 'Username already exists' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = {
        id: users.length + 1,
        username,
        passwordHash: hashedPassword,
        role: 'user'
    };
    
    users.push(newUser);
    res.json({ message: 'Registration successful' });
});

app.get('/api/auth/validate', authenticateToken, (req, res) => {
    res.json({ user: req.user });
});

// User management endpoints
app.get('/api/users', authenticateToken, requireAdmin, (req, res) => {
    res.json(users.map(u => ({
        username: u.username,
        role: u.role
    })));
});

app.post('/api/users', authenticateToken, requireAdmin, (req, res) => {
    const { username, password, role = 'user' } = req.body;
    
    if (users.some(u => u.username === username)) {
        return res.status(400).json({ error: 'Username already exists' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = {
        id: users.length + 1,
        username,
        passwordHash: hashedPassword,
        role
    };
    
    users.push(newUser);
    res.json({ message: 'User created successfully' });
});

app.delete('/api/users/:username', authenticateToken, requireAdmin, (req, res) => {
    const { username } = req.params;
    
    if (username === 'admin') {
        return res.status(403).json({ error: 'Cannot delete admin user' });
    }
    
    const index = users.findIndex(u => u.username === username);
    if (index === -1) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    users.splice(index, 1);
    res.json({ message: 'User deleted successfully' });
});

// Protected calculation endpoint with all security measures
app.post('/api/calculate', 
    authenticateToken,
    validateSignature,
    (req, res) => {
        // Validate inputs
        const { age, amount, term } = req.body;
        
        if (!age || !amount || !term) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        // Generate calculation token
        const calcToken = crypto.createHmac('sha256', SECRET_KEY)
            .update(`${Date.now()}:${JSON.stringify(req.body)}`)
            .digest('hex');
        
        // Perform calculation (simplified)
        const result = {
            premium: (amount * 0.001 * age / term).toFixed(2),
            token: calcToken,
            timestamp: Date.now()
        };
        
        res.json(result);
    }
);

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});