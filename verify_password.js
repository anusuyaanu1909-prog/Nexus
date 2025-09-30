// verify_password.js
const db = require('./db');
const bcrypt = require('bcryptjs');

const username = process.argv[2];   // e.g. 'alice'
const password = process.argv[3];   // e.g. 'pass'

if (!username || !password) {
  console.log('Usage: node verify_password.js <username> <password>');
  process.exit(1);
}

db.get('SELECT password FROM users WHERE username = ?', [username], (err, row) => {
  if (err) return console.error('DB error', err);
  if (!row) return console.log('User not found');
  const ok = bcrypt.compareSync(password, row.password);
  console.log(ok ? 'Password OK' : 'Incorrect password');
  process.exit(0);
});
