const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Use Render's /tmp folder for the database
const dbPath = path.join('/tmp', 'chat.db');

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('DB Error:', err);
    else console.log('SQLite DB connected at', dbPath);
});
// Users table

db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    is_admin INTEGER DEFAULT 0
)`);


// Messages table
db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    receiver TEXT,
    msg TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

module.exports = db;
