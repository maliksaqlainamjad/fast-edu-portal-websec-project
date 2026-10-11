const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'websec',
  password: process.env.DB_PASSWORD || 'websec_pass',
  database: process.env.DB_NAME || 'vuln_edu_portal',
  waitForConnections: true,
  connectionLimit: 10,
});

// VULNERABLE helper: builds raw SQL by string concatenation and uses
// pool.query() with a plain string (no placeholders) so that whatever the
// caller concatenates in is executed exactly as written. This is what makes
// every injection in this version "genuine" against a real MySQL engine.
async function rawQuery(sql) {
  const [rows] = await pool.query(sql);
  return rows;
}

module.exports = { pool, rawQuery };
