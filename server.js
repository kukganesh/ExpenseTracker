require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');

const app = express();

// ─── 1. Security & Middleware ───
app.use(helmet({ contentSecurityPolicy: false })); 
app.use(compression());
app.use(express.json());
app.use(express.static('public'));

// Rate Limiter
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/', limiter);

// ─── 2. Database Setup ───
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
});

// TEST CONNECTION
pool.getConnection()
  .then(conn => {
    console.log('✅ MySQL Connected successfully');
    conn.release();
  })
  .catch(err => {
    console.error('❌ MySQL Connection Failed:', err.message);
  });

// ─── 3. Session Setup (Memory Store) ───
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev_secret_key', 
  resave: false,
  saveUninitialized: false,
  cookie: { 
    httpOnly: true, 
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    secure: false // Set to true only if using HTTPS
  } 
}));

// Make DB available in routes
app.use((req, res, next) => { req.pool = pool; next(); });

// ─── 4. Routes ───
app.use('/', require('./routes/auth'));
app.use('/api/transactions', require('./routes/transactions'));
app.use('/api/subscriptions', require('./routes/subscriptions'));

// ─── 5. Start Server ───
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));