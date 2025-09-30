require('dotenv').config();
const express = require('express');
const app = express();
const http = require('http').createServer(app);
const { Server } = require('socket.io');
const io = new Server(http, { cors: { origin: "*" } });
const db = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ------------------ AUTH ------------------
function authenticateToken(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'No token' });
  const token = auth.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = payload;
    next();
  });
}

// Register
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });

  const hashed = bcrypt.hashSync(password, 8);
  const stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
  stmt.run(username, hashed, function(err) {
    if (err) return res.status(400).json({ error: 'Username taken' });
    const token = jwt.sign({ id: this.lastID, username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username });
  });
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  });
});

// ------------------ SOCKET.IO ------------------
const onlineUsers = {}; // { socketId: username }

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error("No token"));
  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return next(new Error("Invalid token"));
    socket.user = payload;
    next();
  });
});
io.on("connection", (socket) => {
    const username = socket.user.username;

    // Remove previous entries of the same username
    for (const id in onlineUsers) {
        if (onlineUsers[id] === username) delete onlineUsers[id];
    }

    onlineUsers[socket.id] = username;
    io.emit("onlineUsers", [...new Set(Object.values(onlineUsers))]);
});

io.on("connection", (socket) => {
  const username = socket.user.username;
  onlineUsers[socket.id] = username;

  // Update online users
  io.emit("onlineUsers", Object.values(onlineUsers));
socket.on("private message", ({ to, msg }) => {
  // Save message to DB
  const stmt = db.prepare('INSERT INTO messages (sender, receiver, msg) VALUES (?, ?, ?)');
  stmt.run(username, to, msg);

  // Send to the recipient if online
  const targetSocketId = Object.keys(onlineUsers).find(id => onlineUsers[id] === to);
  if (targetSocketId) {
    io.to(targetSocketId).emit("private message", { from: username, msg });
  }

  // Send back to the sender for immediate display
  socket.emit("private message", { from: username, msg });
});




  // Get message history
  socket.on("get history", ({ withUser }) => {
    db.all(`
      SELECT * FROM messages 
      WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
      ORDER BY timestamp ASC
    `, [username, withUser, withUser, username], (err, rows) => {
      if (err) return socket.emit("history", []);
      socket.emit("history", rows.map(r => ({ from: r.sender, msg: r.msg })));
    });
  });

  socket.on("disconnect", () => {
    delete onlineUsers[socket.id];
    io.emit("onlineUsers", Object.values(onlineUsers));
  });
});

// ------------------ START SERVER ------------------
const PORT = process.env.PORT || 3000;
http.listen(PORT, '0.0.0.0', () => console.log(`Server running on http://0.0.0.0:${PORT}`));