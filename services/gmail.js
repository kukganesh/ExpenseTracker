const { google } = require('googleapis');
const crypto = require('crypto');

// ══════════════════════════════════════════════════════════════════════════════
//  ORIGINAL CONFIGURATION & PATTERNS (Restored from server.js)
// ══════════════════════════════════════════════════════════════════════════════

const PROMO_SUBJECT_RE = [
  /\bup to\s*\d+%\s*(off|discount|cashback)\b/i,
  /\bearn\b.{0,20}\bcashback\b.{0,30}\b(next|every|when)\b/i,
  /\bget\b.{0,15}\b\d+%\s*(off|discount)\b/i,
  /\b(mega|big|flash|end of season)\s*sale\b/i,
  /\b(last chance|don.?t miss|ends tonight|ends today)\b/i,
  /\buse code\s+[A-Z0-9]{3,}\b/i,
  /\b(new arrival|just launched|back in stock)\b/i,
  /\b(referral bonus|refer a friend|invite friends)\b/i,
  /\bnewsletter\b|\bunsubscribe\b/i,
];

const PROMO_FROM_RE = [
  /\b(offers?|deals?|newsletter|marketing|campaign|promotions?)\b[^@]*@/i,
  /@[^>]*\b(offers?|deals?|newsletter|marketing|campaign)\b/i,
];

const SKIP_SUBJECT_RE = [
  /\b(shipped|dispatched|out for delivery|arriving|on its way)\b/i,
  /\b(password reset|verify your email|otp|security code|two.factor)\b/i,
  /\b(welcome to|confirm your email|activate your account|email verification)\b/i,
  /\b(survey|rate your experience|how was your (order|ride|experience))\b/i,
  /\b(track your order|shipment update|delivery update|package update)\b/i,
];

const EXPENSE_SUBJECT_PATTERNS = [
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
  { re: /\byour\b.{0,20}\border\b.{0,30}\bfrom\b/i,                       score: 8 },
  { re: /\byour\b.{0,30}\border\s*$/i,                                     score: 6 },
  { re: /^order\b.{0,5}\bfrom\b/i,                                         score: 6 },
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
  { re: /total\s*paid\s*[-:\s]\s*₹\s*[\d,]+/i,                         score: 10 },
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
  { re: /thank you for ordering from/i,                                  score: 7  },
  { re: /(?:debited|deducted)\s*(?:from\s*(?:your\s*)?(?:a\/c|account))?.{0,30}₹\s*[\d,]+/i, score: 9 },
  { re: /₹\s*[\d,]+\s*(?:debited|deducted)\s*from/i,                    score: 9  },
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

const EXPENSE_THRESHOLD = 5;
const CREDIT_THRESHOLD = 7;

// ══════════════════════════════════════════════════════════════════════════════
//  ORIGINAL HELPERS
// ══════════════════════════════════════════════════════════════════════════════

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

  raw = raw
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&#8377;|&#x20b9;/gi, '₹')
    .replace(/â‚¹/g, '₹')
    .replace(/\brs\.?\s*/gi, '₹')
    .replace(/\binr\s*/gi, '₹');

  return raw.replace(/\s{2,}/g, ' ').trim();
}

function isPromotional(subject, from) {
  if (SKIP_SUBJECT_RE.some(r => r.test(subject))) return 'skip';
  if (PROMO_SUBJECT_RE.some(r => r.test(subject))) return 'promo';
  if (PROMO_FROM_RE.some(r => r.test(from))) return 'promo';
  return null;
}

function classifyEmail(subject, body) {
  let expenseScore = 0;
  for (const p of EXPENSE_SUBJECT_PATTERNS) if (p.re.test(subject)) expenseScore += p.score;
  for (const p of EXPENSE_BODY_PATTERNS) if (p.re.test(body)) expenseScore += p.score;

  let refundScore = 0;
  for (const p of REFUND_SUBJECT_PATTERNS) if (p.re.test(subject)) refundScore += p.score;
  for (const p of REFUND_BODY_PATTERNS) if (p.re.test(body)) refundScore += p.score;

  let cashbackScore = 0;
  for (const p of CASHBACK_SUBJECT_PATTERNS) if (p.re.test(subject)) cashbackScore += p.score;
  for (const p of CASHBACK_BODY_PATTERNS) if (p.re.test(body)) cashbackScore += p.score;

  if (refundScore >= CREDIT_THRESHOLD && refundScore >= cashbackScore && refundScore > expenseScore)
    return { type: 'refund', score: refundScore };
  if (cashbackScore >= CREDIT_THRESHOLD && cashbackScore > expenseScore)
    return { type: 'cashback', score: cashbackScore };
  if (expenseScore >= EXPENSE_THRESHOLD)
    return { type: 'expense', score: expenseScore };

  return null;
}

function extractAmount(body, type) {
  const RUPEE_RE = /₹\s*([\d,]+\.?\d*)/g;
  const anchors =
    type === 'expense'
      ? /total\s*paid|(?:order|grand|invoice|bill)?\s*total|amount\s*(?:paid|charged|billed|debited)|you\s*(?:paid|spent)|payment\s*(?:of|amount)|grand\s*total/gi
      : type === 'refund'
      ? /refund(?:ed)?(?:\s+of)?|credited back|has been credited|will be credited|reversal|reimburs/gi
      : /cashback(?:\s+of)?|cash back(?:\s+of)?|coins?\s*(?:added|credited)|reward(?:s)?\s*credited/gi;

  const anchorMatches = [...body.matchAll(anchors)];
  const allAmounts = [...body.matchAll(RUPEE_RE)].map(m => ({
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

  const values = allAmounts.map(a => a.value);
  return type === 'expense' ? Math.max(...values) : Math.min(...values);
}

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
  return null;
}

function extractMerchant(from) {
  const nameMatch = from.match(/^"?([^"<]{2,50}?)"?\s*</);
  if (nameMatch) {
    let name = nameMatch[1].trim()
      .replace(/\s*(support|team|no.?reply|noreply|notifications?|alerts?|orders?|info|help|care|service|billing|invoice|payments?|customer)\s*$/i, '')
      .trim();
    const lower = name.toLowerCase().replace(/\s+/g, '');
    if (KNOWN_MERCHANTS[lower]) return KNOWN_MERCHANTS[lower];
    if (name.length >= 2 && name.length <= 40) return name;
  }

  const domainMatch = from.match(/@([\w.\-]+)/);
  if (!domainMatch) return 'Unknown';

  let domain = domainMatch[1].toLowerCase()
    .replace(/^(mail|mailer|email|info|support|noreply|no-reply|notifications?|orders?|payments?|alerts?|team|accounts?|customer|do-not-reply|billing|transact|connect)\./i, '');

  const tlds = new Set(['com', 'co', 'in', 'net', 'org', 'io', 'app', 'ai', 'biz', 'gov', 'edu']);
  const parts = domain.split('.').filter(p => !tlds.has(p));
  const raw = parts[0] || domain.split('.')[0];

  return KNOWN_MERCHANTS[raw.toLowerCase()] || (raw.charAt(0).toUpperCase() + raw.slice(1));
}

// ══════════════════════════════════════════════════════════════════════════════
//  MAIN LOGIC
// ══════════════════════════════════════════════════════════════════════════════

module.exports = {
  importEmails: async (auth, pool, userId) => {
    const gmail = google.gmail({ version: 'v1', auth });

    const GMAIL_QUERIES = [
      'subject:(confirmed) subject:(order OR booking OR payment OR purchase)',
      'subject:("payment successful" OR "payment confirmed" OR "payment received")',
      'subject:("amount debited" OR "payment debited" OR "transaction successful")',
      'subject:(invoice OR receipt) (₹ OR rs OR inr OR rupee)',
      'subject:("thank you for your order" OR "purchase confirmation" OR "order placed")',
      'subject:("ticket confirmed" OR "booking confirmed" OR "trip receipt")',
      'subject:("subscription confirmed" OR "subscription renewed" OR "membership")',
      'subject:("your order from") from:(zomato.com OR swiggy.com)',
      'subject:("your zomato order" OR "your swiggy order" OR "your blinkit order")',
      'subject:("your order") from:(zomato.com OR swiggy.com OR blinkit.com OR zepto.in OR bigbasket.com)',
      'subject:("debit alert" OR "debited" OR "debit intimation")',
      'subject:(txn OR transaction) (debited OR inr OR "a/c")',
      'subject:(refund OR refunded OR "refund processed" OR "refund initiated")',
      'subject:("money back" OR "cancellation confirmed" OR "order cancelled" OR "return processed")',
      'subject:("amount credited" OR "amount refunded" OR "credit note" OR reversal)',
      '"your refund" (processed OR initiated OR credited)',
      'subject:("cashback credited" OR "cashback added" OR "cash back credited")',
      'subject:("reward credited" OR "supercoins added" OR "wallet credit" OR "points credited")',
    ];

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

    const imported = [], dupes = [];

    for (const msg of allMessages) {
      try {
        const m = await gmail.users.messages.get({ userId: 'me', id: msg.id, format: 'full' });
        const headers = m.data.payload.headers;
        const getH = n => headers.find(h => h.name === n)?.value || '';
        const subject = getH('Subject');
        const from = getH('From');
        const dateHeader = getH('Date');

        const promoCheck = isPromotional(subject, from);
        if (promoCheck === 'skip' || promoCheck === 'promo') continue;

        const body = extractBody(m.data.payload);
        if (!body) continue;

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
          continue;
        }

        const classification = classifyEmail(subject, body);
        if (!classification) continue;
        const { type } = classification;

        const amount = extractAmount(body, type);
        if (!amount || amount < 1) continue;

        const merchant = extractMerchant(from);
        const txDate = dateHeader ? new Date(dateHeader) : new Date();

        const orderId = extractOrderId(body, null);

        let dedupeKey, orderIdToStore;
        if (orderId) {
          dedupeKey = `${userId}_${orderId}_${type}`;
          orderIdToStore = orderId;
        } else {
          const dayKey = txDate.toISOString().slice(0, 10);
          dedupeKey = `${userId}_${merchant}_${dayKey}_${amount}_${type}`;
          orderIdToStore = msg.id; 
        }

        const hash = crypto.createHash('sha256').update(dedupeKey).digest('hex');

        const [result] = await pool.execute(
          `INSERT IGNORE INTO transactions
           (user_id, merchant_name, order_id, amount, transaction_date, transaction_hash, type)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [userId, merchant, orderIdToStore, amount, txDate, hash, type]
        );

        if (result.affectedRows > 0) {
          imported.push({ merchant, amount });
          console.log(`[import] ✓ ${type} ₹${amount} | ${merchant}`);
        } else {
          dupes.push(merchant);
        }

      } catch (msgErr) {
        console.error('[import] message error:', msg.id, msgErr.message);
      }
    }

    return imported.length;
  }
};