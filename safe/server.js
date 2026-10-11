/**
 * FAST Edu-Portal — SAFE (HARDENED) VERSION
 * Web Security Project (Part 2 — Blue Team Focus)
 *
 * Same use case and routes as the vulnerable version, but every
 * vulnerability is fixed:
 *   1. Reflected XSS      -> fixed with EJS auto-escaping (<%= %>)
 *   2. Stored XSS         -> fixed with sanitize-html on input + escaping on output
 *   3. DOM-based XSS       -> fixed with textContent instead of innerHTML
 *   4. CSRF                -> fixed with a per-session CSRF token checked on every POST
 *   5. SQL Injection (all 3 levels) -> fixed with parameterized queries everywhere
 */
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const sanitizeHtml = require('sanitize-html');
const { query } = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// --- FIX #4 (CSRF): session cookie hardened with SameSite=Strict ------
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-to-a-long-random-string',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict' }
}));

// --- FIX #4 (CSRF): per-session random token, verified on every POST --
function ensureCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}
function csrfProtection(req, res, next) {
  const tokenFromForm = req.body._csrf;
  if (!tokenFromForm || tokenFromForm !== req.session.csrfToken) {
    return res.status(403).send('Forbidden: invalid or missing CSRF token. This request was rejected ' +
      'because it did not include the secret, per-session token that only pages served by this ' +
      'application know — exactly what blocks a cross-site forged request.');
  }
  next();
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

app.get('/', (req, res) => res.redirect(req.session.user ? '/dashboard' : '/login'));

// ---------------------------------------------------------------------
// AUTH
// ---------------------------------------------------------------------
app.get('/login', (req, res) => {
  res.render('login', { error: null, mode: 'SAFE', csrfToken: ensureCsrfToken(req) });
});

// --- FIX #5a (SQL Injection, easy): parameterized query ---------------
app.post('/login', csrfProtection, async (req, res) => {
  const { username, password } = req.body;
  try {
    const rows = await query('SELECT * FROM users WHERE username = ? AND password = ?', [username, password]);
    if (rows.length > 0) {
      req.session.user = { id: rows[0].id, username: rows[0].username, role: rows[0].role, full_name: rows[0].full_name };
      return res.redirect('/dashboard');
    }
    res.render('login', { error: 'Invalid username or password', mode: 'SAFE', csrfToken: ensureCsrfToken(req) });
  } catch (e) {
    // Generic message only -> no internal error / schema details leaked
    res.render('login', { error: 'Something went wrong. Please try again.', mode: 'SAFE', csrfToken: ensureCsrfToken(req) });
  }
});

app.get('/register', (req, res) => res.render('register', { error: null, mode: 'SAFE', csrfToken: ensureCsrfToken(req) }));
app.post('/register', csrfProtection, async (req, res) => {
  const { username, password, email, full_name } = req.body;
  try {
    await query('INSERT INTO users (username, password, email, full_name, role) VALUES (?, ?, ?, ?, ?)',
      [username, password, email, full_name, 'student']);
    res.redirect('/login');
  } catch (e) {
    res.render('register', { error: 'Could not create account (username may already be taken).', mode: 'SAFE', csrfToken: ensureCsrfToken(req) });
  }
});

app.get('/logout', (req, res) => { req.session.destroy(() => res.redirect('/login')); });

// --- FIX #5b (SQL Injection, intermediate / blind): parameterized -----
app.get('/forgot-password', (req, res) => {
  res.render('forgot', { result: null, mode: 'SAFE', csrfToken: ensureCsrfToken(req) });
});
app.post('/forgot-password', csrfProtection, async (req, res) => {
  const { username } = req.body;
  let result;
  try {
    const rows = await query('SELECT id FROM users WHERE username = ?', [username]);
    // Same generic message regardless of branch -> no user-enumeration oracle either
    result = 'If an account with that username exists, a reset link has been emailed.';
    void rows;
  } catch (e) {
    result = 'If an account with that username exists, a reset link has been emailed.';
  }
  res.render('forgot', { result, mode: 'SAFE', csrfToken: ensureCsrfToken(req) });
});

// ---------------------------------------------------------------------
// DASHBOARD
// ---------------------------------------------------------------------
app.get('/dashboard', requireLogin, async (req, res) => {
  const courses = await query('SELECT * FROM courses');
  res.render('dashboard', { user: req.session.user, courses, mode: 'SAFE' });
});

// --- FIX #1 (Reflected XSS) + FIX #5c (SQLi advanced/UNION) -----------
// `q` is passed as a bound parameter (never concatenated into SQL), and
// echoed back using EJS's auto-escaping tag (<%= %>), so both the
// injection and the reflected-script vectors are closed at once.
app.get('/search', async (req, res) => {
  const q = req.query.q || '';
  let results = [];
  try {
    results = await query('SELECT id, title, instructor, description FROM courses WHERE title LIKE ?', ['%' + q + '%']);
  } catch (e) {
    results = [];
  }
  res.render('search', { q, results, mode: 'SAFE' });
});

// ---------------------------------------------------------------------
// COURSE PAGE + STORED XSS FIX
// ---------------------------------------------------------------------
app.get('/courses/:id', async (req, res) => {
  const id = Number(req.params.id) || 0;
  const rows = await query('SELECT * FROM courses WHERE id = ?', [id]);
  const course = rows[0];
  if (!course) return res.status(404).send('Course not found');
  const reviews = await query('SELECT * FROM reviews WHERE course_id = ? ORDER BY id DESC', [id]);
  res.render('course', { course, reviews, user: req.session.user, mode: 'SAFE', csrfToken: ensureCsrfToken(req) });
});

// --- FIX #2 (Stored XSS): sanitize on input, escape on output ---------
// Defense in depth: sanitize-html strips <script>, event handlers (onerror,
// onload, ...) and any other active content before the comment is ever
// written to the database, AND the course page renders comments with
// EJS's escaping tag (<%= %>) as a second layer of protection.
app.post('/courses/:id/review', requireLogin, csrfProtection, async (req, res) => {
  const courseId = Number(req.params.id) || 0;
  const cleanComment = sanitizeHtml(req.body.comment || '', { allowedTags: [], allowedAttributes: {} });
  await query('INSERT INTO reviews (course_id, user_id, author_name, comment) VALUES (?, ?, ?, ?)',
    [courseId, req.session.user.id, req.session.user.full_name, cleanComment]);
  res.redirect('/courses/' + courseId);
});

// ---------------------------------------------------------------------
// ACCOUNT SETTINGS + CSRF FIX
// ---------------------------------------------------------------------
app.get('/account', requireLogin, async (req, res) => {
  const rows = await query('SELECT * FROM users WHERE id = ?', [req.session.user.id]);
  const freshUser = { ...req.session.user, email: rows[0] ? rows[0].email : null };
  res.render('account', { user: freshUser, mode: 'SAFE', updated: req.query.updated, csrfToken: ensureCsrfToken(req) });
});

// --- FIX #4 (CSRF): token required + validated -------------------------
app.post('/account/update-email', requireLogin, csrfProtection, async (req, res) => {
  const { email } = req.body;
  await query('UPDATE users SET email = ? WHERE id = ?', [email, req.session.user.id]);
  res.redirect('/account?updated=1');
});

app.listen(PORT, () => {
  console.log(`[SAFE] FAST Edu-Portal running at http://localhost:${PORT}`);
});
