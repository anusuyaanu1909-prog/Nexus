// list_users.js
const db = require('./db');

db.all('SELECT id, username, password FROM users', (err, rows) => {
  if (err) return console.error('DB error:', err);
  console.table(rows);
  process.exit(0);
});
