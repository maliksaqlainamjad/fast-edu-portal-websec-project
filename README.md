# FAST Edu-Portal — Web Security Project (Part 2, Blue Team Focus)

A single project, **two switchable versions** of the same education-portal
web app:

| Folder        | Port | Purpose                                              |
|---------------|------|-------------------------------------------------------|
| `vulnerable/` | 4000 | Deliberately insecure — every attack below works      |
| `safe/`       | 5000 | Same app, hardened — every attack below is blocked    |

**Use case:** a small student portal (login, course catalogue, course
search, course reviews, account/email settings) — the same core
functionality in both versions, so the only difference is security
posture.

**Stack:** Node.js + Express + EJS (server-rendered views) + MySQL 8 (via
`mysql2`). MySQL (not SQLite) was chosen specifically so the Advanced SQL
Injection chain can use real `information_schema` enumeration, exactly as
the assignment describes.

---

## 1. Project structure

```
websec-project/
├── database/
│   ├── schema.sql        # shared table definitions (users, courses, reviews)
│   └── seed.sql           # demo accounts + courses + reviews
├── vulnerable/             # VULNERABLE VERSION — localhost:4000
│   ├── server.js
│   ├── db.js               # string-concatenated queries (intentional)
│   ├── views/               # EJS templates, several use unescaped <%- %>
│   ├── public/js/dashboard.js  # DOM-based XSS sink (innerHTML)
│   └── attack-demo/
│       └── malicious-csrf.html  # CSRF proof-of-concept attacker page
├── safe/                    # SAFE VERSION — localhost:5000
│   ├── server.js
│   ├── db.js               # parameterized queries only
│   ├── views/               # EJS templates, escaped <%= %> everywhere
│   └── public/js/dashboard.js  # DOM-based XSS fix (textContent)
├── docs/
│   └── PAYLOADS.md          # every required payload + where to paste it
│                              + what you should screenshot
├── docker-compose.yml        # optional one-command setup (MySQL + both apps)
└── README.md                 # this file
```

---

## 2. Running it

You can run this either with **Docker Compose** (easiest, no local MySQL
needed) or **manually** against a local MySQL install (what was used to
build and test this project).

### Option A — Docker Compose (recommended)

```bash
docker compose up --build
```

This starts:
- MySQL 8 on `localhost:3306`, auto-initialized from `database/schema.sql`
  and `database/seed.sql` into **two** databases: `vuln_edu_portal` and
  `safe_edu_portal`
- Vulnerable app on **http://localhost:4000**
- Safe app on **http://localhost:5000**

Wait ~15-20 seconds on first run for MySQL to finish initializing before
the apps can connect (Compose will restart them automatically until MySQL
is ready).

### Option B — Manual (local MySQL)

1. Install MySQL 8 and make sure it's running.
2. Create the databases, a user, and load the schema + seed data:

   ```sql
   CREATE DATABASE vuln_edu_portal;
   CREATE DATABASE safe_edu_portal;
   CREATE USER 'websec'@'localhost' IDENTIFIED BY 'websec_pass';
   CREATE USER 'websec'@'127.0.0.1' IDENTIFIED BY 'websec_pass';
   GRANT ALL PRIVILEGES ON vuln_edu_portal.* TO 'websec'@'localhost', 'websec'@'127.0.0.1';
   GRANT ALL PRIVILEGES ON safe_edu_portal.* TO 'websec'@'localhost', 'websec'@'127.0.0.1';
   FLUSH PRIVILEGES;
   ```

   ```bash
   mysql -u root vuln_edu_portal < database/schema.sql
   mysql -u root vuln_edu_portal < database/seed.sql
   mysql -u root safe_edu_portal < database/schema.sql
   mysql -u root safe_edu_portal < database/seed.sql
   ```

3. Install dependencies and run each app (two terminals):

   ```bash
   cd vulnerable
   cp .env.example .env     # defaults already match the user above
   npm install
   npm start                 # -> http://localhost:4000

   # in a second terminal
   cd safe
   cp .env.example .env
   npm install
   npm start                 # -> http://localhost:5000
   ```

### Demo accounts (seeded in both databases)

| username  | password      | role    |
|-----------|---------------|---------|
| `admin`   | `Admin@12345` | admin   |
| `saqlain` | `Student@123` | student |
| `khan`  | `Student@123` | student |

---

## 3. Where every vulnerability/fix lives

| # | Vulnerability | Vulnerable location | Fix in Safe version |
|---|----------------|----------------------|------------------------|
| 1 | Reflected XSS | `GET /search` — `q` echoed with EJS unescaped tag `<%- q %>` | EJS escaped tag `<%= q %>` |
| 2 | Stored XSS | `POST /courses/:id/review` — comment stored & rendered raw (`<%- r.comment %>`) | `sanitize-html` strips tags on save **and** output is escaped (`<%= %>`) |
| 3 | DOM-based XSS | `vulnerable/public/js/dashboard.js` — `location.hash` written via `innerHTML` | `safe/public/js/dashboard.js` — written via `textContent` |
| 4 | CSRF | `POST /account/update-email` — no CSRF token, no `SameSite` hardening | Per-session CSRF token (hidden form field, verified server-side) + `SameSite=Strict` cookie |
| 5a | SQL Injection — Easy | `POST /login` — string-concatenated query | Parameterized query (`?` placeholders) |
| 5b | SQL Injection — Intermediate (blind boolean) | `POST /forgot-password` — oracle leaks "exists"/"not found" | Parameterized query + identical generic response either way |
| 5c | SQL Injection — Advanced (UNION chain) | `GET /search` — `q` concatenated into `LIKE '%q%'` | Parameterized query — `q` is always treated as literal data |

Full payloads for every row above are in **`docs/PAYLOADS.md`**.

---

## 4. Trying the CSRF attack

1. Log in to the **vulnerable** app at http://localhost:4000 (e.g.
   `saqlain` / `Student@123`) and leave that tab open.
2. In a second terminal, serve the attacker page from a different port:
   ```bash
   cd vulnerable/attack-demo
   python3 -m http.server 9000
   ```
3. Visit `http://localhost:9000/malicious-csrf.html` in the **same
   browser**. It auto-submits a hidden form to
   `http://localhost:4000/account/update-email` the instant it loads.
4. Go back to `http://localhost:4000/account` — the email has silently
   changed to `attacker@evil.com`, with no confirmation ever shown to the
   victim.
5. Repeat against the **safe** app on port 5000 (edit the form's `action`
   in `malicious-csrf.html` to point at `:5000` first) — it will fail with
   `403 Forbidden` because the forged request has no valid CSRF token.

---

## 5. Notes for the README you submit to GitHub

- This repo already **is** that submission-ready structure — just push it
  as-is (see §6).
- Both versions share the same schema/seed data but write to **separate
  databases** (`vuln_edu_portal` / `safe_edu_portal`) so exploiting one
  never corrupts the other's demo data.
- Passwords are stored in plaintext in both versions on purpose — the
  assignment is scoped to XSS/CSRF/SQLi, not password hashing, and
  plaintext passwords make the SQLi data-exfiltration step (`SELECT
  username, password ...`) directly demonstrable. Feel free to add
  `bcrypt` hashing to the Safe version for extra credit; it doesn't change
  any of the required attack/fix pairs above.

---

## 6. Pushing to GitHub

```bash
cd websec-project
git init
git add .
git commit -m "Web Security Project Part 2 - vulnerable + safe versions"
git branch -M main
git remote add origin https://github.com/<your-username>/<repo-name>.git
git push -u origin main
```

A `.gitignore` is already included so `node_modules/`, `.env` files, and
local MySQL data volumes are not committed.
