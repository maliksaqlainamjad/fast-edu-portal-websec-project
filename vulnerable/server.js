/**
 * FAST Edu-Portal — VULNERABLE VERSION
 * Web Security Project (Part 2 — Blue Team Focus)
 *
 * This server intentionally contains the following vulnerabilities so they
 * can be demonstrated end-to-end against a real MySQL backend:
 *   1. Reflected XSS      -> GET  /search
 *   2. Stored XSS         -> POST /courses/:id/review
 *   3. DOM-based XSS      -> public/js/dashboard.js (client-side only)
 *   4. CSRF               -> POST /account/update-email
 *   5. SQL Injection      -> POST /login              (EASY)
 *                             GET  /forgot-password    (INTERMEDIATE, blind boolean)
 *                             GET  /search              (ADVANCED, UNION-based chain)
 *
 * DO NOT deploy this code anywhere public. It exists purely for the
 * coursework's "Vulnerable Version" requirement.
 */
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const { rawQuery } = require('./db');

const app = express();
const PORT = process.env.PORT || 4000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// --- VULNERABILITY #4 (CSRF) -----------------------------------------
// No CSRF token anywhere in this app. The session cookie is the ONLY
// credential checked, and SameSite is intentionally left at the (weak)
// default, so any page that can get the victim's browser to fire a POST
// to this origin can change the victim's e-mail address.
app.use(session({
  secret: process.env.SESSION_SECRET || 'vulnerable-insecure-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true } // no CSRF token, no SameSite hardening
}));

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

app.get('/', (req, res) => res.redirect(req.session.user ? '/dashboard' : '/login'));

// ---------------------------------------------------------------------
// AUTH
// ---------------------------------------------------------------------
app.get('/login', (req, res) => {
  res.render('login', { error: null, mode: 'VULNERABLE' });
});

// --- VULNERABILITY #5a: SQL INJECTION (EASY) --------------------------
// Username & password are concatenated directly into the query string.
// Payload: username =  admin' -- 
//          password =  anything
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  try {
    const rows = await rawQuery(sql);
    if (rows.length > 0) {
      req.session.user = { id: rows[0].id, username: rows[0].username, role: rows[0].role, full_name: rows[0].full_name };
      return res.redirect('/dashboard');
    }
    res.render('login', { error: 'Invalid username or password', mode: 'VULNERABLE', lastSql: sql });
  } catch (e) {
    // Errors are shown verbatim -> also helps error-based injection probing
    res.render('login', { error: 'DB ERROR: ' + e.message, mode: 'VULNERABLE', lastSql: sql });
  }
});

app.get('/register', (req, res) => res.render('register', { error: null, mode: 'VULNERABLE' }));
app.post('/register', async (req, res) => {
  const { username, password, email, full_name } = req.body;
  try {
    await rawQuery(`INSERT INTO users (username, password, email, full_name, role) VALUES ('${username}', '${password}', '${email}', '${full_name}', 'student')`);
    res.redirect('/login');
  } catch (e) {
    res.render('register', { error: e.message, mode: 'VULNERABLE' });
  }
});

app.get('/logout', (req, res) => { req.session.destroy(() => res.redirect('/login')); });

// --- VULNERABILITY #5b: SQL INJECTION (INTERMEDIATE — blind boolean) --
// "Forgot password" username-check oracle. The page only ever says
// "exists" / "does not exist" -> attacker must infer data via TRUE/FALSE
// conditions, e.g.:
//   admin' AND '1'='1        -> exists
//   admin' AND '1'='2        -> does not exist
//   admin' AND SUBSTRING(password,1,1)='A'-- -> exists/not (char-by-char)
app.get('/forgot-password', (req, res) => {
  res.render('forgot', { result: null, mode: 'VULNERABLE' });
});
app.post('/forgot-password', async (req, res) => {
  const { username } = req.body;
  const sql = `SELECT id FROM users WHERE username = '${username}'`;
  let result;
  try {
    const rows = await rawQuery(sql);
    result = rows.length > 0
      ? 'An account with that username exists. A reset link would be emailed.'
      : 'No account found with that username.';
  } catch (e) {
    result = 'No account found with that username.'; // errors folded into FALSE branch
  }
  res.render('forgot', { result, mode: 'VULNERABLE', lastSql: sql });
});

// ---------------------------------------------------------------------
// DASHBOARD (DOM-based XSS lives purely in public/js/dashboard.js)
// ---------------------------------------------------------------------
app.get('/dashboard', requireLogin, async (req, res) => {
  const courses = await rawQuery('SELECT * FROM courses');
  res.render('dashboard', { user: req.session.user, courses, mode: 'VULNERABLE' });
});

// --- VULNERABILITY #1 (Reflected XSS) + #5c SQLi (ADVANCED, UNION) ---
// `q` is (a) concatenated straight into the SQL LIKE clause -> UNION-based
// injection chain (columns -> information_schema -> data), and
// (b) echoed back unescaped into the page -> reflected XSS.
// Reflected XSS payload:  <script>alert('Reflected XSS')</script>
// SQLi column count:      pentest' ORDER BY 5-- -
// SQLi union probe:       pentest' UNION SELECT 1,2,3,4-- -
// SQLi table enum:        pentest' UNION SELECT 1,table_name,3,4 FROM information_schema.tables WHERE table_schema=database()-- -
// SQLi column enum:       pentest' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='users'-- -
// SQLi data extraction:   pentest' UNION SELECT 1,CONCAT(username,0x3a,password),3,4 FROM users-- -
app.get('/search', async (req, res) => {
  const q = req.query.q || '';
  let results = [];
  let sqlError = null;
  const sql = `SELECT id, title, instructor, description FROM courses WHERE title LIKE '%${q}%'`;
  try {
    results = await rawQuery(sql);
  } catch (e) {
    sqlError = e.message; // verbose errors help error-based / column-count probing
  }
  res.render('search', { q, results, sqlError, lastSql: sql, mode: 'VULNERABLE' });
});

// ---------------------------------------------------------------------
// COURSE PAGE + STORED XSS
// ---------------------------------------------------------------------
app.get('/courses/:id', async (req, res) => {
  const course = (await rawQuery(`SELECT * FROM courses WHERE id = ${Number(req.params.id) || 0}`))[0];
  if (!course) return res.status(404).send('Course not found');
  const reviews = await rawQuery(`SELECT * FROM reviews WHERE course_id = ${Number(req.params.id) || 0} ORDER BY id DESC`);
  res.render('course', { course, reviews, user: req.session.user, mode: 'VULNERABLE' });
});

// --- VULNERABILITY #2 (Stored XSS) ------------------------------------
// The review comment is stored AS-IS and later rendered with EJS's
// unescaped output tag (<%- %>) on the course page, so a payload like
//   <script>alert('Stored XSS')</script>
// executes for every single visitor who views that course afterwards.
app.post('/courses/:id/review', requireLogin, async (req, res) => {
  const { comment } = req.body;
  const courseId = Number(req.params.id) || 0;
  await rawQuery(`INSERT INTO reviews (course_id, user_id, author_name, comment) VALUES (${courseId}, ${req.session.user.id}, '${req.session.user.full_name}', '${comment.replace(/'/g, "\\'")}')`);
  res.redirect('/courses/' + courseId);
});

// ---------------------------------------------------------------------
// ACCOUNT SETTINGS + CSRF TARGET
// ---------------------------------------------------------------------
app.get('/account', requireLogin, async (req, res) => {
  const rows = await rawQuery(`SELECT * FROM users WHERE id = ${req.session.user.id}`);
  const freshUser = { ...req.session.user, email: rows[0] ? rows[0].email : null };
  res.render('account', { user: freshUser, mode: 'VULNERABLE', updated: req.query.updated });
});

// --- VULNERABILITY #4 (CSRF) ------------------------------------------
// Real, state-changing action (email change) with NO CSRF token and NO
// re-authentication. Only the (automatically-attached) session cookie is
// checked, so vulnerable/attack-demo/malicious-csrf.html can trigger it
// from a different page the instant a logged-in victim opens it.
app.post('/account/update-email', requireLogin, async (req, res) => {
  const { email } = req.body;
  await rawQuery(`UPDATE users SET email = '${email}' WHERE id = ${req.session.user.id}`);
  res.redirect('/account?updated=1');
});

app.listen(PORT, () => {
  console.log(`[VULNERABLE] FAST Edu-Portal running at http://localhost:${PORT}`);
});
