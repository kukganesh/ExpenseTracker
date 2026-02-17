const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { google } = require('googleapis');

// Helper for OAuth
function makeOAuth() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
}

// ─── AUTH ROUTES ───

// 1. Register (POST /api/register)
router.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Missing fields' });
    
    const hash = await bcrypt.hash(password, 12);
    await req.pool.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', [email, hash]);
    res.json({ message: 'Registered successfully' });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') res.status(400).json({ message: 'Email exists' });
    else res.status(500).json({ message: 'Server error' });
  }
});

// 2. Login (POST /api/login)
router.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await req.pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (!rows.length) return res.status(400).json({ message: 'Invalid credentials' });
    
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ message: 'Invalid credentials' });
    
    req.session.userId = user.id;
    req.session.email = user.email;
    res.json({ message: 'Login successful' });
  } catch (e) {
    res.status(500).json({ message: 'Server error' });
  }
});

// 3. Logout (POST /api/logout)
router.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ message: 'Logged out' });
  });
});

// 4. Status (GET /api/status)
// 4. Status (GET /api/status)
router.get('/api/status', (req, res) => {
  if (req.session.userId) {
    res.json({ 
      loggedIn: true, 
      email: req.session.email,
      isGmailConnected: !!req.session.gmailTokens // Returns true if tokens exist
    });
  } else {
    res.json({ loggedIn: false });
  }
});

// 5. Google OAuth Start (GET /auth/google)
router.get('/auth/google', (req, res) => {
  if (!req.session.userId) return res.redirect('/auth.html');
  const url = makeOAuth().generateAuthUrl({
    access_type: 'offline', prompt: 'consent',
    scope: ['https://www.googleapis.com/auth/gmail.readonly']
  });
  res.redirect(url);
});

// 6. Google OAuth Callback (GET /auth/google/callback)
router.get('/auth/google/callback', async (req, res) => {
  try {
    const { tokens } = await makeOAuth().getToken(req.query.code);
    req.session.gmailTokens = tokens;
    res.redirect('/dashboard.html?connected=true');
  } catch (e) {
    console.error('OAuth Error:', e);
    res.redirect('/dashboard.html?error=oauth_failed');
  }
});

module.exports = router;