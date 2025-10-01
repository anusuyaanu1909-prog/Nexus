// db.js
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Use Render's /tmp folder for the database (ephemeral storage)
const dbPath = path.join('/tmp', 'chat.db');

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('DB Error:', err);
  } else {
    console.log('SQLite DB connected at', dbPath);
  }
});

// Run schema creation + migrations in serialize to ensure order
db.serialize(() => {
  // Create tables if they don't exist (base schema)
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`, (err) => {
    if (err) console.error('Error creating users table:', err);
  });

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    receiver TEXT,
    msg TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) console.error('Error creating messages table:', err);
  });

  // Ensure required columns exist on users table. If missing, add them.
  db.all(`PRAGMA table_info(users)`, (err, rows) => {
    if (err) {
      console.error('Failed to read users table info:', err);
      return;
    }

    const existingCols = rows.map(r => r.name);
    const migrations = [
      { name: 'is_admin', spec: 'INTEGER DEFAULT 0' },
      { name: 'is_online', spec: 'INTEGER DEFAULT 0' },
      { name: 'last_seen', spec: 'DATETIME DEFAULT CURRENT_TIMESTAMP' }
    ];

    migrations.forEach(col => {
      if (!existingCols.includes(col.name)) {
        const sql = `ALTER TABLE users ADD COLUMN ${col.name} ${col.spec}`;
        db.run(sql, (alterErr) => {
          if (alterErr) {
            // If column already exists (race/previous run), ignore, otherwise log.
            if (!/duplicate column|already exists/i.test(String(alterErr.message))) {
              console.error(`Failed to add column ${col.name}:`, alterErr);
            } else {
              console.log(`Column ${col.name} already exists (ignored).`);
            }
          } else {
            console.log(`Added missing column '${col.name}' to users table.`);
          }
        });
      } else {
        console.log(`Column '${col.name}' already present.`);
      }
    });
  });
});

module.exports = db;
