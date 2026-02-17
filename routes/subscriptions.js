const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);

// GET Subscriptions
router.get('/', async (req, res) => {
  try {
    const [rows] = await req.pool.execute(
      'SELECT * FROM subscriptions WHERE user_id = ? ORDER BY next_billing_date ASC',
      [req.session.userId]
    );
    
    const totalMonthly = rows.reduce((acc, sub) => {
      let monthlyCost = parseFloat(sub.amount);
      if (sub.billing_cycle === 'yearly') monthlyCost = monthlyCost / 12;
      return acc + monthlyCost;
    }, 0);

    res.json({ subscriptions: rows, total_monthly: totalMonthly });
  } catch (e) { 
    console.error('GET /subscriptions error:', e);
    res.status(500).json({ message: 'Error fetching subscriptions' }); 
  }
});

// ADD Subscription
router.post('/', async (req, res) => {
  console.log('📝 Received Subscription Data:', req.body); // DEBUG LOG

  try {
    const { service_name, amount, cycle, next_date } = req.body;
    
    // Basic Validation
    if (!service_name || !amount) {
      return res.status(400).json({ message: 'Service name and amount are required' });
    }

    // Ensure date is valid (or null if empty)
    const validDate = next_date ? new Date(next_date) : null;

    await req.pool.execute(
      `INSERT INTO subscriptions (user_id, service_name, amount, billing_cycle, next_billing_date) 
       VALUES (?, ?, ?, ?, ?)`,
      [req.session.userId, service_name, amount, cycle, validDate]
    );

    console.log('✅ Subscription saved to DB'); // DEBUG LOG
    res.json({ message: 'Added' });

  } catch (e) { 
    console.error('❌ Database Insert Error:', e.message); // REAL ERROR LOG
    res.status(500).json({ message: 'Database error: ' + e.message }); 
  }
});

// DELETE Subscription
router.delete('/:id', async (req, res) => {
  try {
    await req.pool.execute(
      'DELETE FROM subscriptions WHERE id = ? AND user_id = ?', 
      [req.params.id, req.session.userId]
    );
    res.json({ message: 'Deleted' });
  } catch (e) { res.status(500).json({ message: 'Error deleting' }); }
});

module.exports = router;