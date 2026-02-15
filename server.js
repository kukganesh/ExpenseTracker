require('dotenv').config();

const express = require('express');
const mysql   = require('mysql2/promise');
const bcrypt  = require('bcrypt');
const session = require('express-session');
const crypto  = require('crypto');
const { google } = require('googleapis');

const app = express();

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use(express.static('public'));

// ─── MySQL ─────────────────────────────────────────────────────────────────────
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
});
pool.getConnection()
  .then(c => { console.log('MySQL connected'); c.release(); })
  .catch(e => console.error('MySQL error:', e));

// ─── Auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ message: 'Not authenticated' });
  next();
}

// ─── Auth routes ──────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });
    const hash = await bcrypt.hash(password, 12);
    await pool.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', [email, hash]);
    res.json({ message: 'Registered successfully' });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(400).json({ message: 'Email already registered' });
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (!rows.length) return res.status(400).json({ message: 'Invalid credentials' });
    const user = rows[0];
    if (!(await bcrypt.compare(password, user.password_hash)))
      return res.status(400).json({ message: 'Invalid credentials' });
    req.session.userId = user.id;
    req.session.email  = user.email;
    res.json({ message: 'Login successful' });
  } catch (e) { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => { res.clearCookie('connect.sid'); res.json({ message: 'Logged out' }); });
});

app.get('/api/status', (req, res) => {
  req.session.userId
    ? res.json({ loggedIn: true, email: req.session.email })
    : res.json({ loggedIn: false });
});

// ─── Data routes ──────────────────────────────────────────────────────────────
app.get('/api/summary', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT
        SUM(CASE WHEN type='expense'  THEN amount ELSE 0 END) AS total_expense,
        SUM(CASE WHEN type='refund'   THEN amount ELSE 0 END) AS total_refund,
        SUM(CASE WHEN type='cashback' THEN amount ELSE 0 END) AS total_cashback,
        COUNT(CASE WHEN type='expense'  THEN 1 END)           AS expense_count,
        COUNT(CASE WHEN type='refund'   THEN 1 END)           AS refund_count,
        COUNT(CASE WHEN type='cashback' THEN 1 END)           AS cashback_count
       FROM transactions WHERE user_id = ?`, [req.session.userId]);
    const d        = rows[0] || {};
    const expense  = parseFloat(d.total_expense)  || 0;
    const refund   = parseFloat(d.total_refund)   || 0;
    const cashback = parseFloat(d.total_cashback) || 0;
    res.json({
      total_expense:   expense,
      total_refund:    refund,
      total_cashback:  cashback,
      expense_count:   parseInt(d.expense_count)  || 0,
      refund_count:    parseInt(d.refund_count)    || 0,
      cashback_count:  parseInt(d.cashback_count)  || 0,
      net_spending:    expense - refund - cashback
    });
  } catch (e) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/transactions', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT * FROM transactions WHERE user_id = ?
       ORDER BY transaction_date DESC`, [req.session.userId]);
    res.json(rows);
  } catch (e) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/merchant-summary', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT
         merchant_name,
         SUM(CASE WHEN type='expense'  THEN amount ELSE 0 END) AS total_expense,
         SUM(CASE WHEN type='refund'   THEN amount ELSE 0 END) AS total_refund,
         SUM(CASE WHEN type='cashback' THEN amount ELSE 0 END) AS total_cashback,
         (SUM(CASE WHEN type='expense'  THEN amount ELSE 0 END)
          - SUM(CASE WHEN type='refund'   THEN amount ELSE 0 END)
          - SUM(CASE WHEN type='cashback' THEN amount ELSE 0 END)) AS net_spend
       FROM transactions WHERE user_id = ?
       GROUP BY merchant_name
       ORDER BY total_expense DESC`, [req.session.userId]);
    res.json(rows);
  } catch (e) { res.status(500).json({ message: 'Server error' }); }
});

// ─── OAuth ─────────────────────────────────────────────────────────────────────
function makeOAuth() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
}

app.get('/auth/google', requireAuth, (req, res) => {
  const url = makeOAuth().generateAuthUrl({
    access_type: 'offline', prompt: 'consent',
    scope: ['https://www.googleapis.com/auth/gmail.readonly']
  });
  res.redirect(url);
});

app.get('/auth/google/callback', requireAuth, async (req, res) => {
  try {
    const { tokens } = await makeOAuth().getToken(req.query.code);
    req.session.gmailTokens = tokens;
    res.redirect('/dashboard.html?connected=true');
  } catch (e) {
    console.error('OAuth error:', e);
    res.redirect('/dashboard.html?error=oauth_failed');
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  GMAIL IMPORT ENGINE
// ══════════════════════════════════════════════════════════════════════════════

// ── 1. Body extraction ────────────────────────────────────────────────────────
function extractBody(payload) {
  const decode = d => Buffer.from(d, 'base64url').toString('utf-8');

  function gather(parts, plains, htmls) {
    for (const p of (parts || [])) {
      if (p.mimeType === 'text/plain' && p.body?.data) plains.push(decode(p.body.data));
      else if (p.mimeType === 'text/html' && p.body?.data) htmls.push(decode(p.body.data));
      if (p.parts) gather(p.parts, plains, htmls);
    }
  }

  let raw = '';
  if (payload.parts) {
    const plains = [], htmls = [];
    gather(payload.parts, plains, htmls);
    raw = plains.length ? plains.join('\n') : htmls.join('\n');
  }
  if (!raw && payload.body?.data) raw = decode(payload.body.data);
  if (!raw) return '';

  // Strip CSS / scripts / HTML tags
  raw = raw
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ');

  // Decode HTML entities
  raw = raw
    .replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&#8377;|&#x20b9;/gi, '₹')
    .replace(/â‚¹/g, '₹');

  // Normalise all currency spellings to ₹
  raw = raw
    .replace(/\brs\.?\s*/gi, '₹')
    .replace(/\binr\s*/gi, '₹');

  return raw.replace(/\s{2,}/g, ' ').trim();
}

// ── 2. Promo / non-financial guard ────────────────────────────────────────────
// Only block things that are CLEARLY promotional or non-financial.
// Keep this list tight — false positives here cause missing transactions.

const PROMO_SUBJECT_RE = [
  /\bup to\s*\d+%\s*(off|discount|cashback)\b/i,          // "up to 50% off"
  /\bearn\b.{0,20}\bcashback\b.{0,30}\b(next|every|when)\b/i, // "earn cashback on next order"
  /\bget\b.{0,15}\b\d+%\s*(off|discount)\b/i,             // "get 30% off"
  /\b(mega|big|flash|end of season)\s*sale\b/i,
  /\b(last chance|don.?t miss|ends tonight|ends today)\b/i,
  /\buse code\s+[A-Z0-9]{3,}\b/i,                         // "use code FLAT200"
  /\b(new arrival|just launched|back in stock)\b/i,
  /\b(referral bonus|refer a friend|invite friends)\b/i,
  /\bnewsletter\b|\bunsubscribe\b/i,
];

const PROMO_FROM_RE = [
  /\b(offers?|deals?|newsletter|marketing|campaign|promotions?)\b[^@]*@/i,
  /@[^>]*\b(offers?|deals?|newsletter|marketing|campaign)\b/i,
];

// Hard skip — definitely not financial
const SKIP_SUBJECT_RE = [
  /\b(shipped|dispatched|out for delivery|arriving|on its way)\b/i,
  /\b(password reset|verify your email|otp|security code|two.factor)\b/i,
  /\b(welcome to|confirm your email|activate your account|email verification)\b/i,
  /\b(survey|rate your experience|how was your (order|ride|experience))\b/i,
  /\b(track your order|shipment update|delivery update|package update)\b/i,
];

function isPromotional(subject, from) {
  if (SKIP_SUBJECT_RE.some(r => r.test(subject)))  return 'skip';
  if (PROMO_SUBJECT_RE.some(r => r.test(subject))) return 'promo';
  if (PROMO_FROM_RE.some(r => r.test(from)))        return 'promo';
  return null;
}

// ── 3. Scoring classifier ─────────────────────────────────────────────────────
//
// KEY FIX: Subject patterns now allow words BETWEEN "order" and "confirmed"
// e.g. "Your order is confirmed", "Order has been placed", "order successfully placed"
//
// Also: subject-only score of 7+ is enough for expenses (the Gmail query already
// filtered for financial emails, so a matching subject is strong signal).

const EXPENSE_SUBJECT_PATTERNS = [
  // Standard confirmations (allow words between "order" and "confirmed/placed")
  { re: /\border\b.{0,15}\b(confirmed|placed|successful|received)\b/i,    score: 8 },
  { re: /\bpayment\b.{0,15}\b(confirmed|successful|received|done|complete)\b/i, score: 8 },
  { re: /\b(purchase|booking)\b.{0,15}\b(confirmed|successful|placed)\b/i, score: 8 },
  { re: /\bthank you for (your )?(order|purchase|payment|shopping)\b/i,    score: 8 },
  { re: /\binvoice\b.{0,20}\b(for|from|generated|attached)\b/i,           score: 7 },
  { re: /\b(receipt|bill)\b.{0,15}\b(for|from|generated)\b/i,             score: 7 },
  { re: /\bpurchase\s*confirmation\b/i,                                    score: 9 },
  { re: /\bticket.{0,10}(confirmed|booked|booking confirmed)\b/i,          score: 8 },
  { re: /\bbooking.{0,10}confirmed\b/i,                                    score: 8 },
  { re: /\bamount\s*debited\b/i,                                           score: 9 },
  { re: /\bpayment\s*debited\b/i,                                          score: 9 },
  { re: /\btransaction\b.{0,15}\b(successful|confirmed|complete)\b/i,      score: 7 },
  { re: /\bsubscription\b.{0,20}\b(confirmed|activated|renewed|started)\b/i, score: 7 },
  { re: /\b(order|trip|ride|purchase)\s*(receipt|summary|details|invoice)\b/i, score: 8 },
  { re: /\bconfirmed[!.]?\s*$/i,                                           score: 5 },
  // Food delivery: "Your Zomato order from Hotel X" / "Your Swiggy order from McDs"
  { re: /\byour\b.{0,20}\border\b.{0,30}\bfrom\b/i,                       score: 8 },
  // "Your Blinkit order" / "Your Zepto order" / "Your Amazon.in order"
  { re: /\byour\b.{0,30}\border\s*$/i,                                     score: 6 },
  // "Order from Nykaa" / "Order from Zomato"
  { re: /^order\b.{0,5}\bfrom\b/i,                                         score: 6 },
  // Bank debit alerts: "Debit Alert" / "A/c debited" / "HDFC Txn of INR 500"
  { re: /\bdebit\s*(alert|notification|intimation)\b/i,                    score: 8 },
  { re: /\ba\/c\b.{0,30}\bdebited\b/i,                                     score: 9 },
  { re: /\baccount\b.{0,20}\bdebited\b/i,                                  score: 9 },
  { re: /\btxn\b.{0,20}\b(of|for)\b.{0,10}(inr|rs)/i,                    score: 8 },
  { re: /\b(inr|rs\.?)\s*[\d,]+.{0,20}\bdebited\b/i,                      score: 9 },
];

const EXPENSE_BODY_PATTERNS = [
  { re: /payment\s*(?:of\s*)?₹\s*[\d,]+\s*(?:was|has been|is)\s*(?:successful|confirmed|received|processed)/i, score: 10 },
  { re: /₹\s*[\d,]+\s*(?:was|has been)\s*debited/i,                     score: 10 },
  { re: /amount\s*(?:of\s*)?₹\s*[\d,]+\s*(?:debited|charged|paid)/i,   score: 10 },
  { re: /(?:order|grand|invoice)\s*total\s*[:\-]?\s*₹\s*[\d,]+/i,      score: 9  },
  { re: /total\s*(?:amount\s*)?(?:paid|charged|billed)\s*[:\-]?\s*₹\s*[\d,]+/i, score: 9 },
  // NEW: "Total paid - ₹174.32" (Zomato format) / "Total paid: ₹X"
  { re: /total\s*paid\s*[-:\s]\s*₹\s*[\d,]+/i,                         score: 10 },
  // NEW: "Amount paid: ₹X" / "Amount: ₹X" in bank alerts
  { re: /amount\s*[:\-]\s*₹\s*[\d,]+/i,                                 score: 7  },
  { re: /you\s*(?:have\s*)?(?:paid|spent)\s*₹\s*[\d,]+/i,              score: 8  },
  { re: /charged\s*(?:to\s*your)?.{0,30}₹\s*[\d,]+/i,                  score: 8  },
  { re: /thank you for (your )?(order|purchase|payment|shopping)/i,     score: 7  },
  { re: /your\s*(?:order|booking|purchase)\b.{0,30}\b(?:confirmed|placed|successful)/i, score: 7 },
  { re: /(?:order|booking)\s*(?:id|no|number|#)\s*[:\-]?\s*[A-Z0-9]/i, score: 5  },
  { re: /invoice\s*(?:no|number|#)?.{0,20}₹\s*[\d,]+/i,                score: 7  },
  { re: /billed\s*(?:amount\s*)?[:\-]?\s*₹\s*[\d,]+/i,                 score: 8  },
  { re: /total\s*[:\-]?\s*₹\s*[\d,]+/i,                                score: 7  },
  { re: /₹\s*[\d,]+\s*(?:only|paid|total)/i,                            score: 6  },
  // NEW: "thank you for ordering from X" — Zomato's exact body phrase
  { re: /thank you for ordering from/i,                                  score: 7  },
  // NEW: UPI/bank debit body formats
  { re: /(?:debited|deducted)\s*(?:from\s*(?:your\s*)?(?:a\/c|account))?.{0,30}₹\s*[\d,]+/i, score: 9 },
  { re: /₹\s*[\d,]+\s*(?:debited|deducted)\s*from/i,                    score: 9  },
  // Negatives
  { re: /refund(?:ed)?\s*(?:of\s*)?₹/i,                                score: -10 },
  { re: /has been refunded|refund processed|refund initiated/i,         score: -10 },
  { re: /credited back to your/i,                                       score: -8  },
  { re: /cashback\s*(?:of\s*)?₹.{0,20}(?:credited|added)/i,            score: -8  },
];

const REFUND_SUBJECT_PATTERNS = [
  { re: /\brefund(ed)?\b/i,                                    score: 5 },
  { re: /\bmoney.?back\b/i,                                    score: 5 },
  { re: /\brefund\b.{0,20}\b(processed|initiated|successful)\b/i, score: 8 },
  { re: /\bamount\b.{0,15}\b(refunded|credited back)\b/i,      score: 8 },
  { re: /\b(order|booking)\b.{0,10}\bcancell(ed|ation)\b/i,   score: 4 },
  { re: /\breturn\b.{0,15}\b(processed|accepted|approved)\b/i, score: 7 },
  { re: /\bcancellation\b.{0,15}\b(confirmed|successful)\b/i,  score: 6 },
  { re: /\bcredit.?note\b/i,                                   score: 6 },
  { re: /\breimburse(ment|d)?\b/i,                             score: 6 },
  { re: /\breversal\b/i,                                       score: 5 },
];

const REFUND_BODY_PATTERNS = [
  { re: /refund of\s*₹\s*[\d,]+/i,                                      score: 10 },
  { re: /₹\s*[\d,]+\s*(?:has been|will be)\s*refunded/i,                score: 10 },
  { re: /refund\s*(?:of\s*)?₹\s*[\d,]+\s*(?:has been|is)\s*(?:processed|initiated|credited)/i, score: 10 },
  { re: /your refund (?:of|for|amounting)/i,                             score: 9  },
  { re: /we.?ve (processed|initiated) (your )?refund/i,                  score: 9  },
  { re: /refund\s*(?:has been\s*)?successfully\s*(processed|initiated|credited)/i, score: 9 },
  { re: /amount.{0,20}refunded.{0,30}(?:bank|account|wallet|upi)/i,     score: 8  },
  { re: /credited back to your\s*(?:bank|account|card|wallet)/i,        score: 8  },
  { re: /will be (?:credited|refunded).{0,40}(?:\d+.?\d*)\s*(?:working|business)?\s*days/i, score: 8 },
  { re: /return.{0,30}refund.{0,30}₹/i,                                 score: 7  },
  { re: /cancell(?:ed|ation).{0,40}₹.{0,40}refund/i,                   score: 7  },
  { re: /refund.{0,30}(?:neft|imps|upi|wallet)/i,                       score: 7  },
  { re: /your order.{0,30}cancell/i,                                     score: 4  },
  // Negatives
  { re: /payment (?:successful|confirmed|received)/i,                    score: -8 },
  { re: /order (?:placed|confirmed|received)/i,                          score: -8 },
  { re: /thank you for your (?:purchase|payment|order)/i,                score: -7 },
  { re: /₹\s*[\d,]+\s*(?:was|has been)\s*debited/i,                     score: -10},
  { re: /amount debited/i,                                               score: -9 },
];

const CASHBACK_SUBJECT_PATTERNS = [
  { re: /\bcashback\b.{0,15}\b(credited|added|received)\b/i,           score: 8 },
  { re: /\bcash back\b.{0,15}\b(credited|added)\b/i,                   score: 8 },
  { re: /\breward(s)?\b.{0,15}\b(credited|added|earned)\b/i,           score: 7 },
  { re: /\bsupercoins?\b.{0,15}\b(added|credited)\b/i,                 score: 8 },
  { re: /\bwallet\b.{0,10}\bcredit\b/i,                                score: 6 },
  { re: /\bpoints?\b.{0,15}\b(credited|added)\b/i,                     score: 6 },
];

const CASHBACK_BODY_PATTERNS = [
  { re: /cashback of\s*₹\s*[\d,]+.{0,20}(?:credited|added)/i,          score: 10 },
  { re: /₹\s*[\d,]+\s*cashback\s*(?:has been|is)\s*(?:credited|added)/i, score: 10 },
  { re: /we.?ve added\s*₹\s*[\d,]+.{0,20}(?:cashback|reward)/i,        score: 9  },
  { re: /your (cashback|reward|supercoins?).{0,30}₹\s*[\d,]+.{0,20}(?:credited|added)/i, score: 9 },
  { re: /₹\s*[\d,]+\s*(?:supercoins?|coins?|points?).{0,20}(?:credited|added)/i, score: 8 },
  { re: /cashback.{0,30}credited.{0,20}(?:wallet|account|paytm|phonepe|gpay)/i, score: 8 },
  { re: /you.?ve earned\s*₹\s*[\d,]+\s*cashback/i,                     score: 9  },
  { re: /earn.*cashback.*next|cashback on your next/i,                   score: -8 },
  { re: /up to\s*₹\s*[\d,]+\s*cashback/i,                               score: -7 },
  { re: /payment (?:successful|confirmed)/i,                             score: -6 },
];

// FIX: lower threshold for expenses to 5, keep 7 for refunds/cashback
// Expenses: a subject-only match of 8 is sufficient (Gmail already filtered)
// Refunds/Cashback: need body corroboration to avoid false positives
const EXPENSE_THRESHOLD  = 5;
const CREDIT_THRESHOLD   = 7;

function classifyEmail(subject, body) {
  let expenseScore = 0;
  for (const p of EXPENSE_SUBJECT_PATTERNS) if (p.re.test(subject)) expenseScore += p.score;
  for (const p of EXPENSE_BODY_PATTERNS)    if (p.re.test(body))    expenseScore += p.score;

  let refundScore = 0;
  for (const p of REFUND_SUBJECT_PATTERNS) if (p.re.test(subject)) refundScore += p.score;
  for (const p of REFUND_BODY_PATTERNS)    if (p.re.test(body))    refundScore += p.score;

  let cashbackScore = 0;
  for (const p of CASHBACK_SUBJECT_PATTERNS) if (p.re.test(subject)) cashbackScore += p.score;
  for (const p of CASHBACK_BODY_PATTERNS)     if (p.re.test(body))    cashbackScore += p.score;

  // Refunds and cashback must beat CREDIT_THRESHOLD and beat expense score
  if (refundScore >= CREDIT_THRESHOLD && refundScore >= cashbackScore && refundScore > expenseScore)
    return { type: 'refund', score: refundScore };
  if (cashbackScore >= CREDIT_THRESHOLD && cashbackScore > expenseScore)
    return { type: 'cashback', score: cashbackScore };
  // Expenses only need EXPENSE_THRESHOLD
  if (expenseScore >= EXPENSE_THRESHOLD)
    return { type: 'expense', score: expenseScore };

  return null;
}

// ── 4. Amount extraction ──────────────────────────────────────────────────────
// For EXPENSES:  largest amount near "total/charged/paid" anchor
// For REFUNDS:   smallest near "refund/credited" anchor
// For CASHBACK:  smallest near "cashback/reward" anchor

function extractAmount(body, type) {
  const RUPEE_RE = /₹\s*([\d,]+\.?\d*)/g;

  const anchors =
    type === 'expense'
      ? /total\s*paid|(?:order|grand|invoice|bill)?\s*total|amount\s*(?:paid|charged|billed|debited)|you\s*(?:paid|spent)|payment\s*(?:of|amount)|grand\s*total/gi
      : type === 'refund'
      ? /refund(?:ed)?(?:\s+of)?|credited back|has been credited|will be credited|reversal|reimburs/gi
      : /cashback(?:\s+of)?|cash back(?:\s+of)?|coins?\s*(?:added|credited)|reward(?:s)?\s*credited/gi;

  const anchorMatches = [...body.matchAll(anchors)];
  const allAmounts    = [...body.matchAll(RUPEE_RE)].map(m => ({
    value: parseFloat(m[1].replace(/,/g, '')),
    index: m.index
  })).filter(a => a.value >= 1 && a.value <= 1000000);

  if (!allAmounts.length) return null;

  if (anchorMatches.length) {
    const nearby = [];
    for (const anchor of anchorMatches) {
      for (const amt of allAmounts) {
        if (Math.abs(amt.index - anchor.index) <= 300) nearby.push(amt.value);
      }
    }
    if (nearby.length) {
      return type === 'expense' ? Math.max(...nearby) : Math.min(...nearby);
    }
  }

  // Fallback: no anchor found
  const values = allAmounts.map(a => a.value);
  return type === 'expense' ? Math.max(...values) : Math.min(...values);
}

// ── 5. Order ID extraction ─────────────────────────────────────────────────────
function extractOrderId(body, fallback) {
  const patterns = [
    /\b(?:order|booking)\s*(?:id|no\.?|number|#)\s*[:\-#]?\s*([A-Z0-9_\-\/]{5,30})/i,
    /\binvoice\s*(?:id|no\.?|number|#)\s*[:\-]?\s*([A-Z0-9_\-\/]{5,30})/i,
    /\btransaction\s*(?:id|no\.?|number|#)\s*[:\-]?\s*([A-Z0-9_\-\/]{6,30})/i,
    /\brefund\s*(?:id|no\.?|number|#)\s*[:\-]?\s*([A-Z0-9_\-\/]{5,30})/i,
    /\breference\s*(?:id|no\.?|number|#)?\s*[:\-]?\s*([A-Z0-9_\-]{6,30})/i,
    /\bpnr\s*[:\-]?\s*([A-Z0-9]{6,15})/i,
    /\bupi\s*ref\s*(?:no\.?)?\s*[:\-]?\s*(\d{10,})/i,
    /#([A-Z0-9_\-]{6,30})\b/,
  ];
  for (const pat of patterns) {
    const m = body.match(pat);
    if (m?.[1]) return m[1].trim().toUpperCase();
  }
  return null; // Return null, NOT the msg.id — handled in dedup logic below
}

// ── 6. Merchant name ──────────────────────────────────────────────────────────
const KNOWN_MERCHANTS = {
  amazon: 'Amazon', flipkart: 'Flipkart', myntra: 'Myntra', ajio: 'AJIO',
  nykaa: 'Nykaa', meesho: 'Meesho', snapdeal: 'Snapdeal', tatacliq: 'Tata CLiQ',
  swiggy: 'Swiggy', zomato: 'Zomato', blinkit: 'Blinkit', zepto: 'Zepto',
  bigbasket: 'BigBasket', dunzo: 'Dunzo', instamart: 'Instamart',
  paytm: 'Paytm', phonepe: 'PhonePe', gpay: 'Google Pay',
  razorpay: 'Razorpay', cashfree: 'Cashfree', juspay: 'Juspay',
  makemytrip: 'MakeMyTrip', goibibo: 'Goibibo', cleartrip: 'Cleartrip',
  easemytrip: 'EaseMyTrip', redbus: 'redBus', indigo: 'IndiGo', airindia: 'Air India',
  airtel: 'Airtel', jio: 'Jio', vodafone: 'Vodafone Vi', bsnl: 'BSNL',
  irctc: 'IRCTC', ola: 'Ola', uber: 'Uber', rapido: 'Rapido',
  cred: 'CRED', slice: 'Slice', simpl: 'Simpl', lazypay: 'LazyPay',
  hdfc: 'HDFC Bank', icici: 'ICICI Bank', sbi: 'SBI', axis: 'Axis Bank',
  kotak: 'Kotak Bank', idfcfirst: 'IDFC First', payu: 'PayU',
  netflix: 'Netflix', spotify: 'Spotify', hotstar: 'Hotstar',
  bookmyshow: 'BookMyShow', swipe: 'Swipe', ixigo: 'ixigo',
};

function extractMerchant(from) {
  // 1. Try display name: "Zomato Order <noreply@zomato.com>"
  const nameMatch = from.match(/^"?([^"<]{2,50}?)"?\s*</);
  if (nameMatch) {
    let name = nameMatch[1].trim()
      // Strip trailing noise words
      .replace(/\s*(support|team|no.?reply|noreply|notifications?|alerts?|orders?|info|help|care|service|billing|invoice|payments?|customer)\s*$/i, '')
      .trim();
    // Use known merchant map first if the cleaned name matches
    const lower = name.toLowerCase().replace(/\s+/g, '');
    if (KNOWN_MERCHANTS[lower]) return KNOWN_MERCHANTS[lower];
    if (name.length >= 2 && name.length <= 40) return name;
  }

  // 2. Extract from domain
  const domainMatch = from.match(/@([\w.\-]+)/);
  if (!domainMatch) return 'Unknown';

  let domain = domainMatch[1].toLowerCase()
    .replace(/^(mail|mailer|email|info|support|noreply|no-reply|notifications?|orders?|payments?|alerts?|team|accounts?|customer|do-not-reply|billing|transact|connect)\./i, '');

  const tlds = new Set(['com','co','in','net','org','io','app','ai','biz','gov','edu']);
  const parts = domain.split('.').filter(p => !tlds.has(p));
  const raw = parts[0] || domain.split('.')[0];

  return KNOWN_MERCHANTS[raw.toLowerCase()] || (raw.charAt(0).toUpperCase() + raw.slice(1));
}

// ── 7. Gmail queries ──────────────────────────────────────────────────────────
const GMAIL_QUERIES = [
  // EXPENSE — standard confirmations
  'subject:(confirmed) subject:(order OR booking OR payment OR purchase)',
  'subject:("payment successful" OR "payment confirmed" OR "payment received")',
  'subject:("amount debited" OR "payment debited" OR "transaction successful")',
  'subject:(invoice OR receipt) (₹ OR rs OR inr OR rupee)',
  'subject:("thank you for your order" OR "purchase confirmation" OR "order placed")',
  'subject:("ticket confirmed" OR "booking confirmed" OR "trip receipt")',
  'subject:("subscription confirmed" OR "subscription renewed" OR "membership")',
  // NEW: Food delivery apps — subject is just "Your X order from Restaurant"
  'subject:("your order from") from:(zomato.com OR swiggy.com)',
  'subject:("your zomato order" OR "your swiggy order" OR "your blinkit order")',
  'subject:("your order") from:(zomato.com OR swiggy.com OR blinkit.com OR zepto.in OR bigbasket.com)',
  // NEW: Bank/UPI debit alerts
  'subject:("debit alert" OR "debited" OR "debit intimation")',
  'subject:(txn OR transaction) (debited OR inr OR "a/c")',
  // REFUND
  'subject:(refund OR refunded OR "refund processed" OR "refund initiated")',
  'subject:("money back" OR "cancellation confirmed" OR "order cancelled" OR "return processed")',
  'subject:("amount credited" OR "amount refunded" OR "credit note" OR reversal)',
  '"your refund" (processed OR initiated OR credited)',
  // CASHBACK
  'subject:("cashback credited" OR "cashback added" OR "cash back credited")',
  'subject:("reward credited" OR "supercoins added" OR "wallet credit" OR "points credited")',
];

// ── 8. Main import endpoint ───────────────────────────────────────────────────
app.get('/api/gmail/import', requireAuth, async (req, res) => {
  if (!req.session.gmailTokens)
    return res.status(400).json({ message: 'Gmail not connected. Please connect first.' });

  try {
    const oauth2Client = makeOAuth();
    oauth2Client.setCredentials(req.session.gmailTokens);

    if (req.session.gmailTokens.expiry_date && Date.now() > req.session.gmailTokens.expiry_date) {
      const { credentials } = await oauth2Client.refreshAccessToken();
      req.session.gmailTokens = credentials;
      oauth2Client.setCredentials(credentials);
    }

    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    // Collect unique message IDs across all queries
    const seenMsgIds = new Set();
    const allMessages = [];

    for (const q of GMAIL_QUERIES) {
      try {
        const list = await gmail.users.messages.list({ userId: 'me', maxResults: 50, q });
        for (const msg of (list.data.messages || [])) {
          if (!seenMsgIds.has(msg.id)) {
            seenMsgIds.add(msg.id);
            allMessages.push(msg);
          }
        }
      } catch (qErr) {
        console.warn(`[import] Query failed: "${q}" — ${qErr.message}`);
      }
    }

    console.log(`[import] ${allMessages.length} unique candidate emails`);

    const imported = [], skipped = [], rejected = [], dupes = [];

    for (const msg of allMessages) {
      try {
        const m = await gmail.users.messages.get({ userId: 'me', id: msg.id, format: 'full' });
        const headers    = m.data.payload.headers;
        const getH       = n => headers.find(h => h.name === n)?.value || '';
        const subject    = getH('Subject');
        const from       = getH('From');
        const dateHeader = getH('Date');

        // Guard 1: hard skip
        const promoCheck = isPromotional(subject, from);
        if (promoCheck === 'skip') { skipped.push({ reason: 'non-financial', subject }); continue; }
        if (promoCheck === 'promo') { rejected.push({ reason: 'promotional', subject }); continue; }

        // Guard 2: extract body
        const body = extractBody(m.data.payload);
        if (!body) { skipped.push({ reason: 'empty body', subject }); continue; }

        // Guard 3: promo body check (only reject if strong promo + no strong tx signal)
        const STRONG_PROMO_BODY = [
          /earn\s*(?:up to\s*)?₹\s*[\d,]+\s*cashback\s*on\s*(your\s*next|every)/i,
          /get\s*(?:up to\s*)?₹\s*[\d,]+\s*(cashback|off|discount)\s*on\s*(your\s*next|every)/i,
          /use\s*code\s+[A-Z0-9]{3,}\s+to\s+(?:get|avail)/i,
        ];
        const STRONG_TX_BODY = [
          /payment\s*(?:of\s*)?₹\s*[\d,]+\s*(?:successful|confirmed|received|debited)/i,
          /₹\s*[\d,]+\s*(?:was|has been)\s*debited/i,
          /your\s*(?:order|booking)\b.{0,30}\b(?:confirmed|placed)/i,
          /refund\s*(?:of\s*)?₹\s*[\d,]+\s*(?:has been|will be)\s*(?:processed|credited)/i,
          /cashback\s*of\s*₹\s*[\d,]+\s*(?:has been|is)\s*(?:credited|added)/i,
        ];
        if (STRONG_PROMO_BODY.some(r => r.test(body)) && !STRONG_TX_BODY.some(r => r.test(body))) {
          rejected.push({ reason: 'promo body', subject }); continue;
        }

        // Guard 4: classify
        const classification = classifyEmail(subject, body);
        if (!classification) { skipped.push({ reason: 'unclassified', subject }); continue; }
        const { type } = classification;

        // Guard 5: extract amount
        const amount = extractAmount(body, type);
        if (!amount || amount < 1) { skipped.push({ reason: 'no amount', subject }); continue; }

        const merchant = extractMerchant(from);
        const txDate   = dateHeader ? new Date(dateHeader) : new Date();

        // ── DEDUP FIX ──────────────────────────────────────────────────────────
        // Strategy: try to find a real order ID in the body first.
        // If found → hash by (userId, orderId, type) so that multiple emails
        //   about the same order (confirmation + invoice + receipt) collapse to 1.
        // If not found → hash by (userId, merchant, date-day, amount, type)
        //   so different transactions on the same day are kept but re-syncing
        //   the same email doesn't create duplicates.
        // We NEVER use msg.id in the hash — that caused the duplicates.

        const orderId = extractOrderId(body, null);

        let dedupeKey, orderIdToStore;
        if (orderId) {
          // Real order ID found — collapse all emails for this order+type
          dedupeKey      = `${req.session.userId}_${orderId}_${type}`;
          orderIdToStore = orderId;
        } else {
          // No order ID — use merchant + date-day + amount + type as natural key
          const dayKey   = txDate.toISOString().slice(0, 10); // YYYY-MM-DD
          dedupeKey      = `${req.session.userId}_${merchant}_${dayKey}_${amount}_${type}`;
          orderIdToStore = msg.id; // store msg.id just for reference, not for dedup
        }

        const hash = crypto.createHash('sha256').update(dedupeKey).digest('hex');

        const [result] = await pool.execute(
          `INSERT IGNORE INTO transactions
           (user_id, merchant_name, order_id, amount, transaction_date, transaction_hash, type)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [req.session.userId, merchant, orderIdToStore, amount, txDate, hash, type]
        );

        if (result.affectedRows > 0) {
          imported.push({ merchant, amount, type, orderId: orderIdToStore });
          console.log(`[import] ✓ ${type.padEnd(8)} ₹${amount} | ${merchant} | ${orderIdToStore || '(no id)'}`);
        } else {
          dupes.push({ merchant, orderId: orderIdToStore });
        }

      } catch (msgErr) {
        console.error('[import] message error:', msg.id, msgErr.message);
      }
    }

    console.log(`[import] Done — ${imported.length} new | ${dupes.length} dupes | ${skipped.length} skipped | ${rejected.length} rejected`);

    res.json({
      imported_count:  imported.length,
      duplicate_count: dupes.length,
      skipped_count:   skipped.length,
      rejected_count:  rejected.length,
      imported
    });

  } catch (err) {
    console.error('[import] fatal error:', err);
    res.status(500).json({ message: 'Import failed: ' + err.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));