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
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const JWT_SECRET = process.env.JWT_SECRET || 'nexus_chat_secret_2024';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadsDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'profile-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: function (req, file, cb) {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ------------------ DATABASE SETUP ------------------
db.serialize(() => {
    // Users table with enhanced fields
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        profile_picture TEXT,
        status TEXT DEFAULT 'Online',
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_online BOOLEAN DEFAULT 0,
        is_admin BOOLEAN DEFAULT 0
    )`);

    // Messages table with enhanced fields
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        msg TEXT,
        msg_type TEXT DEFAULT 'text',
        file_url TEXT,
        is_read BOOLEAN DEFAULT 0,
        is_edited BOOLEAN DEFAULT 0,
        is_deleted BOOLEAN DEFAULT 0,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Groups table
    db.run(`CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        description TEXT,
        created_by TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Group members table
    db.run(`CREATE TABLE IF NOT EXISTS group_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER,
        username TEXT,
        is_admin BOOLEAN DEFAULT 0,
        joined_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Group messages table
    db.run(`CREATE TABLE IF NOT EXISTS group_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER,
        sender TEXT,
        msg TEXT,
        msg_type TEXT DEFAULT 'text',
        file_url TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Create admin user if not exists
    const adminPassword = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 8);
    db.run(`INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)`, 
        [ADMIN_USERNAME, adminPassword, 1]);
});

// ------------------ MIDDLEWARE ------------------
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

function isAdmin(req, res, next) {
    db.get('SELECT is_admin FROM users WHERE username = ?', [req.user.username], (err, user) => {
        if (err || !user || !user.is_admin) {
            return res.status(403).json({ error: 'Admin access required' });
        }
        next();
    });
}

// ------------------ ROUTES ------------------

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

        // Update user as online
        db.run('UPDATE users SET is_online = 1, last_seen = CURRENT_TIMESTAMP WHERE username = ?', [username]);

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ 
            token, 
            username: user.username,
            isAdmin: user.is_admin === 1,
            profilePicture: user.profile_picture
        });
    });
});

// Upload profile picture
app.post('/api/upload-profile', authenticateToken, upload.single('profile'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const profilePicture = `/uploads/${req.file.filename}`;
    
    db.run('UPDATE users SET profile_picture = ? WHERE username = ?', [profilePicture, req.user.username], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ profilePicture });
    });
});

// Get user profile
app.get('/api/profile/:username', authenticateToken, (req, res) => {
    const { username } = req.params;
    
    db.get('SELECT username, profile_picture, status, last_seen, is_online FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    });
});

// Update user status
app.put('/api/profile/status', authenticateToken, (req, res) => {
    const { status } = req.body;
    
    db.run('UPDATE users SET status = ? WHERE username = ?', [status, req.user.username], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ message: 'Status updated' });
    });
});

// Admin routes
app.get('/api/admin/users', authenticateToken, isAdmin, (req, res) => {
    db.all('SELECT id, username, profile_picture, status, last_seen, is_online, is_admin FROM users', (err, users) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(users);
    });
});

app.get('/api/admin/messages', authenticateToken, isAdmin, (req, res) => {
    const { limit = 100, offset = 0 } = req.query;
    
    db.all(`
        SELECT m.*, u1.profile_picture as sender_picture, u2.profile_picture as receiver_picture 
        FROM messages m 
        LEFT JOIN users u1 ON m.sender = u1.username 
        LEFT JOIN users u2 ON m.receiver = u2.username 
        ORDER BY m.timestamp DESC 
        LIMIT ? OFFSET ?
    `, [limit, offset], (err, messages) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(messages);
    });
});

app.delete('/api/admin/messages/:id', authenticateToken, isAdmin, (req, res) => {
    const { id } = req.params;
    
    db.run('DELETE FROM messages WHERE id = ?', [id], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ message: 'Message deleted' });
    });
});

// Group routes
app.post('/api/groups', authenticateToken, (req, res) => {
    const { name, description, members } = req.body;
    
    db.run('INSERT INTO groups (name, description, created_by) VALUES (?, ?, ?)', 
        [name, description, req.user.username], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        const groupId = this.lastID;
        // Add creator as admin
        db.run('INSERT INTO group_members (group_id, username, is_admin) VALUES (?, ?, ?)', 
            [groupId, req.user.username, 1]);
        
        // Add other members
        if (members && Array.isArray(members)) {
            members.forEach(member => {
                db.run('INSERT INTO group_members (group_id, username) VALUES (?, ?)', 
                    [groupId, member]);
            });
        }
        
        res.json({ groupId, message: 'Group created successfully' });
    });
});

app.get('/api/groups', authenticateToken, (req, res) => {
    db.all(`
        SELECT g.*, gm.username 
        FROM groups g 
        JOIN group_members gm ON g.id = gm.group_id 
        WHERE gm.username = ?
    `, [req.user.username], (err, groups) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(groups);
    });
});

// ------------------ SOCKET.IO ------------------
const onlineUsers = {};
const typingUsers = {};

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
    
    // Update user as online
    db.run('UPDATE users SET is_online = 1, last_seen = CURRENT_TIMESTAMP WHERE username = ?', [username]);
    
    // Broadcast updated online users
    io.emit("onlineUsers", Object.values(onlineUsers));
    io.emit("userStatus", { username, status: 'online' });

    // Private messaging
    socket.on("private message", ({ to, msg, msgType = 'text', fileUrl = null }) => {
        const messageData = {
            from: username,
            to,
            msg,
            msgType,
            fileUrl,
            timestamp: new Date().toISOString()
        };

        // Save message to DB
        const stmt = db.prepare('INSERT INTO messages (sender, receiver, msg, msg_type, file_url) VALUES (?, ?, ?, ?, ?)');
        stmt.run(username, to, msg, msgType, fileUrl);

        // Send to recipient if online
        const targetSocketId = Object.keys(onlineUsers).find(id => onlineUsers[id] === to);
        if (targetSocketId) {
            io.to(targetSocketId).emit("private message", messageData);
        }

        // Send back to sender for immediate display
        socket.emit("private message", messageData);
        
        // Notify admin if admin is online
        const adminSocketId = Object.keys(onlineUsers).find(id => onlineUsers[id] === ADMIN_USERNAME);
        if (adminSocketId) {
            io.to(adminSocketId).emit("newMessage", messageData);
        }
    });

    // Typing indicators
    socket.on("typing", ({ to, isTyping }) => {
        const targetSocketId = Object.keys(onlineUsers).find(id => onlineUsers[id] === to);
        if (targetSocketId) {
            io.to(targetSocketId).emit("typing", { from: username, isTyping });
        }
    });

    // Read receipts
    socket.on("markRead", ({ from }) => {
        db.run('UPDATE messages SET is_read = 1 WHERE sender = ? AND receiver = ? AND is_read = 0', 
            [from, username]);
        
        const senderSocketId = Object.keys(onlineUsers).find(id => onlineUsers[id] === from);
        if (senderSocketId) {
            io.to(senderSocketId).emit("messageRead", { by: username });
        }
    });

    // Message editing
    socket.on("editMessage", ({ messageId, newContent, to }) => {
        db.run('UPDATE messages SET msg = ?, is_edited = 1 WHERE id = ? AND sender = ?', 
            [newContent, messageId, username], function(err) {
            if (this.changes > 0) {
                const targetSocketId = Object.keys(onlineUsers).find(id => onlineUsers[id] === to);
                if (targetSocketId) {
                    io.to(targetSocketId).emit("messageEdited", { messageId, newContent });
                }
                socket.emit("messageEdited", { messageId, newContent });
            }
        });
    });

    // Message deletion
    socket.on("deleteMessage", ({ messageId, to }) => {
        db.run('UPDATE messages SET is_deleted = 1 WHERE id = ? AND sender = ?', 
            [messageId, username], function(err) {
            if (this.changes > 0) {
                const targetSocketId = Object.keys(onlineUsers).find(id => onlineUsers[id] === to);
                if (targetSocketId) {
                    io.to(targetSocketId).emit("messageDeleted", { messageId });
                }
                socket.emit("messageDeleted", { messageId });
            }
        });
    });

    // Group messaging
    socket.on("groupMessage", ({ groupId, msg, msgType = 'text', fileUrl = null }) => {
        const messageData = {
            groupId,
            from: username,
            msg,
            msgType,
            fileUrl,
            timestamp: new Date().toISOString()
        };

        // Save to group messages
        db.run('INSERT INTO group_messages (group_id, sender, msg, msg_type, file_url) VALUES (?, ?, ?, ?, ?)',
            [groupId, username, msg, msgType, fileUrl]);

        // Get group members and send to all online members
        db.all('SELECT username FROM group_members WHERE group_id = ?', [groupId], (err, members) => {
            if (members) {
                members.forEach(member => {
                    const memberSocketId = Object.keys(onlineUsers).find(id => onlineUsers[id] === member.username);
                    if (memberSocketId && member.username !== username) {
                        io.to(memberSocketId).emit("groupMessage", messageData);
                    }
                });
            }
        });

        socket.emit("groupMessage", messageData);
    });

    // Get message history
    socket.on("get history", ({ withUser }) => {
        db.all(`
            SELECT * FROM messages 
            WHERE ((sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?))
            AND is_deleted = 0
            ORDER BY timestamp ASC
        `, [username, withUser, withUser, username], (err, rows) => {
            if (err) return socket.emit("history", []);
            socket.emit("history", rows.map(r => ({ 
                id: r.id,
                from: r.sender, 
                msg: r.msg,
                msgType: r.msg_type,
                fileUrl: r.file_url,
                isEdited: r.is_edited,
                timestamp: r.timestamp
            })));
        });
    });

    // Get group history
    socket.on("getGroupHistory", ({ groupId }) => {
        db.all(`
            SELECT gm.*, u.profile_picture 
            FROM group_messages gm 
            LEFT JOIN users u ON gm.sender = u.username 
            WHERE gm.group_id = ? 
            ORDER BY gm.timestamp ASC
        `, [groupId], (err, rows) => {
            if (err) return socket.emit("groupHistory", []);
            socket.emit("groupHistory", rows);
        });
    });

    socket.on("disconnect", () => {
        delete onlineUsers[socket.id];
        
        // Update user as offline
        db.run('UPDATE users SET is_online = 0, last_seen = CURRENT_TIMESTAMP WHERE username = ?', [username]);
        
        io.emit("onlineUsers", Object.values(onlineUsers));
        io.emit("userStatus", { username, status: 'offline' });
    });
});

// ------------------ START SERVER ------------------ 
const PORT = process.env.PORT || 3000;
http.listen(PORT, '0.0.0.0', () => {
    console.log(`Nexus Chat Server running on http://0.0.0.0:${PORT}`);
    console.log(`Admin username: ${ADMIN_USERNAME}`);
});