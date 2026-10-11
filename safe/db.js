const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'websec',
  password: process.env.DB_PASSWORD || 'websec_pass',
  database: process.env.DB_NAME || 'safe_edu_portal',
  waitForConnections: true,
  connectionLimit: 10,
});

// SAFE helper: ALWAYS uses parameterized queries (placeholders '?').
// mysql2 sends the SQL text and the values separately to the server, so
// user input can never change the structure of the query, no matter what
// characters it contains. This is the fix for every SQL injection point
// in the vulnerable version.
async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

module.exports = { pool, query };
