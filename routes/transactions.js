const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const gmailService = require('../services/gmail');
const { google } = require('googleapis');

router.use(requireAuth);

// 1. Get Summary (Cards)
router.get('/summary', async (req, res) => {
  try {
    const [rows] = await req.pool.execute(
      `SELECT
        SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) AS total_expense,
        SUM(CASE WHEN type='refund' THEN amount ELSE 0 END) AS total_refund,
        SUM(CASE WHEN type='cashback' THEN amount ELSE 0 END) AS total_cashback,
        COUNT(CASE WHEN type='expense' THEN 1 END) AS expense_count,
        COUNT(CASE WHEN type='refund' THEN 1 END) AS refund_count,
        COUNT(CASE WHEN type='cashback' THEN 1 END) AS cashback_count
       FROM transactions WHERE user_id = ?`, [req.session.userId]);
       
    const d = rows[0] || {};
    res.json({
      total_expense: parseFloat(d.total_expense) || 0,
      total_refund: parseFloat(d.total_refund) || 0,
      total_cashback: parseFloat(d.total_cashback) || 0,
      expense_count: parseInt(d.expense_count) || 0,
      refund_count: parseInt(d.refund_count) || 0,
      cashback_count: parseInt(d.cashback_count) || 0,
      net_spending: (parseFloat(d.total_expense) || 0) - (parseFloat(d.total_refund) || 0) - (parseFloat(d.total_cashback) || 0)
    });
  } catch (e) { res.status(500).json({ message: 'Error' }); }
});

// 2. Get Transactions (List)
router.get('/', async (req, res) => {
  try {
    let sql = 'SELECT * FROM transactions WHERE user_id = ?';
    const params = [req.session.userId];
    
    if (req.query.type && req.query.type !== 'all') {
      sql += ' AND type = ?';
      params.push(req.query.type);
    }
    
    sql += ' ORDER BY transaction_date DESC LIMIT 100';
    const [rows] = await req.pool.execute(sql, params);
    res.json(rows);
  } catch (e) { res.status(500).json({ message: 'Error' }); }
});

// 3. Add Manual Transaction (New Feature)
router.post('/', async (req, res) => {
  try {
    const { merchant_name, amount, type, date, notes } = req.body;
    if (!merchant_name || !amount) return res.status(400).json({ message: 'Missing fields' });

    await req.pool.execute(
      `INSERT INTO transactions (user_id, merchant_name, amount, type, transaction_date, notes, is_manual)
       VALUES (?, ?, ?, ?, ?, ?, TRUE)`,
      [req.session.userId, merchant_name, amount, type, date || new Date(), notes || '']
    );
    res.json({ message: 'Saved' });
  } catch (e) { res.status(500).json({ message: 'Error' }); }
});

// 4. Delete Transaction
router.delete('/:id', async (req, res) => {
  try {
    await req.pool.execute('DELETE FROM transactions WHERE id = ? AND user_id = ?', [req.params.id, req.session.userId]);
    res.json({ message: 'Deleted' });
  } catch (e) { res.status(500).json({ message: 'Error' }); }
});

// 5. Merchant Summary (Chart)
router.get('/merchant-summary', async (req, res) => {
  try {
    const [rows] = await req.pool.execute(
      `SELECT merchant_name, SUM(amount) as total_expense
       FROM transactions WHERE user_id = ? AND type = 'expense'
       GROUP BY merchant_name ORDER BY total_expense DESC LIMIT 10`,
       [req.session.userId]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ message: 'Error' }); }
});

// 6. Sync Gmail (Import)
router.get('/sync', async (req, res) => {
  if (!req.session.gmailTokens) return res.status(400).json({ message: 'Gmail not connected' });
  
  try {
    const oauth2Client = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);
    oauth2Client.setCredentials(req.session.gmailTokens);
    
    // Refresh token check
    if (req.session.gmailTokens.expiry_date && Date.now() > req.session.gmailTokens.expiry_date) {
      const { credentials } = await oauth2Client.refreshAccessToken();
      req.session.gmailTokens = credentials;
      oauth2Client.setCredentials(credentials);
    }

    const count = await gmailService.importEmails(oauth2Client, req.pool, req.session.userId);
    res.json({ imported_count: count });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Sync failed' });
  }
});

module.exports = router;