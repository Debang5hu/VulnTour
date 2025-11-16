/*
 * Deliberately vulnerable Node.js + Express API (SQLite)
 * WARNING: Unsafe code. Run in an isolated VM/container for lab testing only.
 * 
 * just a playground to pentest with modern frameworks :)
 * @debang5hu
 * 
 * 
 * 
 * 
 * 
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const morgan = require('morgan');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
require('dotenv').config();

// db setup
const DB_FILE = process.env.DB_FILE || 'database.sqlite3';
const isNew = !fs.existsSync(DB_FILE);
const db = new Database(DB_FILE);

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'mychemicalromance';  // weak secret key

// store pass
const saltRounds = 12;


if (isNew) {
  const init_sql = fs.readFileSync('./init.sql', 'utf8');
  db.exec(init_sql);
  console.log('Initialized new SQLite database.');
}

// express js
const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

// rate limit
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,   // to change later
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);




// CORS Config
const rawOrigins = process.env.CORS_ORIGINS || 'http://localhost:3000, http://127.0.0.1, http://localhost';
const allowedOrigins = rawOrigins.split(',').map(s => s.trim()).filter(Boolean);

console.log('[DEBUG] Allowed origins:', allowedOrigins);

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
        console.log('[CORS] Allowed:', origin);  //debug
        return callback(null, true);
    }

    console.warn('Blocked CORS origin:', origin);
    return callback(null, false);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Requested-With'],
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));  // browser preflight

// utility
function makeId(prefix = 'id', lenBytes = 8) {
  return prefix + crypto.randomBytes(lenBytes).toString('hex');
}



function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET);
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);  // INSECURE: does not enforce algorithms strictly
  } catch (e) {
    return null;
  }
}

// auth
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  const token = auth.split(' ')[1];
  const data = verifyToken(token);
  if (!data) return res.status(401).json({ error: 'Invalid token' });
  req.user = data;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'No user' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// --- Auth endpoints ---
app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing' });

  const id = 'u' + makeId(6);
  bcrypt.hash(password, saltRounds, (err, hash) => {
  if (err) return res.status(500).json({ error: 'Hashing failed' });
  
  const stmt = db.prepare('INSERT INTO users (id, username, password, email, role) VALUES (?, ?, ?, ?, ?)');
  try {
    stmt.run(id, username, hash, email || null, 'user');
    res.json({ success: true, id });
  } catch (e) {
    res.status(400).json({ error: 'user exists or invalid', detail: e.message });
  }
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'missing' });

  const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!row) return res.status(401).json({ error: 'Bad creds' });

  bcrypt.compare(password, row.password, (err, ok) => {
    if (err) return res.status(500).json({ error: 'server error' });
    if (!ok) return res.status(401).json({ error: 'Bad creds' });

    // produce token password hash (sensitive data exposure)
    const token = signToken({ id: row.id, username: row.username, role: row.role, password: row.password });
    res.json({ token });
  });
});



// CRUD
app.get('/api/users', requireAuth, (req, res) => {
  const search = req.query.search?.trim().toLowerCase() || '';

  let rows;

  if (search) {
    rows = db.prepare(`
      SELECT id, username, email, role 
      FROM users 
      WHERE LOWER(username) LIKE ?
    `).all(`%${search}%`);
  } else {
    rows = db.prepare(`
      SELECT id, username, email, role 
      FROM users
    `).all();
  }

  res.json(rows);
});


app.post('/api/users/:id', requireAuth, (req, res) => {
  const u = db.prepare('SELECT id, username, email, role FROM users WHERE id = ?').get(req.params.id);  // idor
  if (!u) return res.status(404).json({ error: 'not found' });
  res.json(u);
});

app.put('/api/users/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'missing' });

  // mass assignment
  const allowed = Object.keys(req.body);
  if (allowed.length === 0) return res.json(user);
  const setParts = allowed.map(k => `${k} = @${k}`).join(', ');
  const sql = `UPDATE users SET ${setParts} WHERE id = @id`;
  const params = Object.assign({}, req.body, { id });
  try {
    db.prepare(sql).run(params);
    const updated = db.prepare('SELECT id, username, password, email, role FROM users WHERE id = ?').get(id);
    res.json(updated);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.delete('/api/users/:id', requireAuth, (req, res) => {
  try {
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// --- Tours ---
app.get('/api/tours', requireAuth, (req, res) => {
  const page = Math.max(1, parseInt(req.query.page)) || 1;
  const limit = Math.min(100, parseInt(req.query.limit)) || 10;
  const offset = (page - 1) * limit;

  const tours = db.prepare('SELECT * FROM tours LIMIT ? OFFSET ?').all(limit, offset);
  const total = db.prepare('SELECT COUNT(*) as count FROM tours').get().count;

  res.json({
    total,
    page,
    totalPages: Math.ceil(total / limit),
    tours
  });
});

app.post('/api/tours', requireAuth, (req, res) => {
  const id = 't' + makeId(6);
  const ownerId = req.user && req.user.id;
  const title = req.body.title;
  const price = req.body.price || 0;
  const groupId = 'g' + makeId(6);
  
  db.prepare('INSERT INTO groups (id, name, destination) VALUES (?, ?, ?)').run(groupId, title, null);
  db.prepare('INSERT INTO tours (id, title, price, ownerId, groupId) VALUES (?, ?, ?, ?, ?)').run(id, title, price, ownerId, groupId);

  const tour = db.prepare('SELECT * FROM tours WHERE id = ?').get(id);
  res.json(tour);
});



app.put('/api/tours/:id', requireAuth, (req, res) => {
  const tour = db.prepare('SELECT * FROM tours WHERE id = ?').get(req.params.id);
  if (!tour) return res.status(404).json({ error: 'no' });

  if (tour.ownerId !== req.user.id) return res.status(403).json({ error: 'not owner' });

  // mass-assign update
  const allowed = Object.keys(req.body);
  const setParts = allowed.map(k => `${k} = @${k}`).join(', ');
  const sql = `UPDATE tours SET ${setParts} WHERE id = @id`;
  const params = Object.assign({}, req.body, { id: tour.id });
  db.prepare(sql).run(params);
  const updated = db.prepare('SELECT * FROM tours WHERE id = ?').get(tour.id);
  res.json(updated);
});

app.delete('/api/tours/:id', requireAuth, (req, res) => {
  const tour = db.prepare('SELECT * FROM tours WHERE id = ?').get(req.params.id);
  if (!tour) return res.status(404).json({ error: 'no' });
  if (tour.ownerId !== req.user.id) return res.status(403).json({ error: 'not owner' });
  db.prepare('DELETE FROM tours WHERE id = ?').run(tour.id);
  res.json({ success: true });
});


app.post('/api/tours/:id/join', requireAuth, (req, res) => {
  const tourId = req.params.id;
  const userId = req.user.id;

  const tour = db.prepare('SELECT * FROM tours WHERE id = ?').get(tourId);
  if (!tour) return res.status(404).json({ error: 'Tour not found' });

  try {
    db.prepare('INSERT INTO tour_joins (tourId, userId) VALUES (?, ?)').run(tourId, userId);
    if (tour.groupId) {
      db.prepare('INSERT OR IGNORE INTO group_members (groupId, userId) VALUES (?, ?)').run(tour.groupId, userId);
    }
    res.json({ success: true, tourId });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});


app.post('/api/tours/:id/notify-creator', requireAuth, (req, res) => {
  const tourId = req.params.id;
  // Lookup tour and owner
  const tour = db.prepare('SELECT * FROM tours WHERE id = ?').get(tourId);
  if (!tour) return res.status(404).json({ error: 'Tour not found' });

  // Simulated: you may log or create a notification
  console.log(`[Notify] User ${req.user.username} joined tour ${tour.title}. Notify owner: ${tour.ownerId}`);

  res.json({ ok: true, notified: tour.ownerId });
});



// bookings (business logic flaws)
/*app.post('/api/bookings', requireAuth, (req, res) => {
  const tour = db.prepare('SELECT * FROM tours WHERE id = ?').get(req.body.tourId);
  if (!tour) return res.status(404).json({ error: 'tour missing' });

  // BUSINESS FLAW: pricePaid is taken from request body if provided
  const id = 'b' + makeId(6);
  const pricePaid = req.body.pricePaid || tour.price;
  const userId = req.user.id;
  db.prepare('INSERT INTO bookings (id, tourId, userId, pricePaid, status) VALUES (?, ?, ?, ?, ?)').run(id, tour.id, userId, pricePaid, 'confirmed');
  const booking = db.prepare('SELECT * FROM bookings WHERE id = ?').get(id);
  res.json(booking);
});

app.get('/api/bookings/:id', requireAuth, (req, res) => {
  const b = db.prepare('SELECT * FROM bookings WHERE id = ?').get(req.params.id);
  if (!b) return res.status(404).json({ error: 'none' });
  res.json(b);
});

app.put('/api/bookings/:id/refund', requireAuth, (req, res) => {
  const b = db.prepare('SELECT * FROM bookings WHERE id = ?').get(req.params.id);
  if (!b) return res.status(404).json({ error: 'no' });

  if (b.status === 'refunded') return res.json({ success: false, msg: 'already refunded' });
  db.prepare('UPDATE bookings SET status = ? WHERE id = ?').run('refunded', b.id);
  const updated = db.prepare('SELECT * FROM bookings WHERE id = ?').get(b.id);
  res.json({ success: true, refundedBooking: updated });
});*/

// --- Admin insecure deserialization endpoint ---
app.post('/api/admin/query', requireAuth, requireAdmin, (req, res) => {
  const q = req.body.q;
  try {
    const result = eval(q);   // rce
    res.json({ ok: true, result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- Token demo ---
app.get('/api/token-demo', (req, res) => {
  const token = signToken({ id: 'u2', username: 'bob', role: 'admin' });
  res.json({ token });
});

// to do
// open redirect
app.get('/oauth/authorize', (req, res) => {
  const redirect = req.query.redirect_uri || '/';
  // INTENTIONALLY: naive allow-list check (matches substring) leading to open redirect bypass
  const whitelist = ['http://127.0.0.1:5000', 'https://127.0.0.1:5000','http://localhost:5000']; // update accordingly
  const ok = whitelist.find(w => redirect.startsWith(w));
  if (!ok) return res.status(400).send('invalid redirect');
  // In real flow we'd generate code; here we redirect with a fake code
  res.redirect(302, redirect + '?code=426c40690e028415861dbd34d97b1629');
});


// GET friends list
app.get('/api/friend', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.username
    FROM friends f
    JOIN users u ON u.id = f.friendId
    WHERE f.userId = ?
  `).all(req.user.id);
  res.json({ friends: rows });
});


// add
app.post('/api/friend', requireAuth, (req, res) => {
  const friendUsername = req.body.username;
  if (!friendUsername) return res.status(400).json({ error: 'Missing username' });
  
  const friend = db.prepare('SELECT id FROM users WHERE username = ?').get(friendUsername);
  if (!friend) return res.status(404).json({ error: 'User not found' });

  // prevent adding self
  if (friend.id === req.user.id) return res.status(400).json({ error: 'Cannot add self' });

  try {
    db.prepare('INSERT INTO friends (userId, friendId) VALUES (?, ?)').run(req.user.id, friend.id);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: 'Already friends or invalid', detail: e.message });
  }
});


// del
app.delete('/api/friend/:username', requireAuth, (req, res) => {
  const friend = db.prepare('SELECT id FROM users WHERE username = ?').get(req.params.username);
  if (!friend) return res.status(404).json({ error: 'User not found' });

  db.prepare('DELETE FROM friends WHERE userId = ? AND friendId = ?').run(req.user.id, friend.id);
  res.json({ success: true });
});


// Get incoming friend requests
app.get('/api/friend/request', requireAuth, (req, res) => {
  const requests = db.prepare(`
    SELECT fr.fromUserId AS id, u.username
    FROM friend_requests fr
    JOIN users u ON fr.fromUserId = u.id
    WHERE fr.toUserId = ? AND fr.status = 'pending'
  `).all(req.user.id);
  res.json(requests);
});

// send request
app.post('/api/friend/request', requireAuth, (req, res) => {
  const username = req.body.username;
  if (!username) return res.status(400).json({ error: 'Missing username' });

  const toUser = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (!toUser) return res.status(404).json({ error: 'User not found' });
  if (toUser.id === req.user.id) return res.status(400).json({ error: 'Cannot request yourself' });

  // Check pending or accepted in either direction to prevent duplicates or loops
  const existing = db.prepare(`
    SELECT * FROM friend_requests 
    WHERE ((fromUserId = ? AND toUserId = ?) OR (fromUserId = ? AND toUserId = ?))
    AND status IN ('pending', 'accepted')
  `).get(req.user.id, toUser.id, toUser.id, req.user.id);

  const alreadyFriends = db.prepare(`
    SELECT * FROM friends 
    WHERE (userId = ? AND friendId = ?) OR (userId = ? AND friendId = ?)
  `).get(req.user.id, toUser.id, toUser.id, req.user.id);

  if (existing) return res.status(400).json({ error: 'Friend request already exists or accepted' });
  if (alreadyFriends) return res.status(400).json({ error: 'Already friends' });

  try {
    db.prepare('INSERT INTO friend_requests (fromUserId, toUserId, status) VALUES (?, ?, ?)').run(req.user.id, toUser.id, 'pending');
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


// accept
app.post('/api/friend/request/:id/accept', requireAuth, (req, res) => {
  const fromUserId = req.params.id;
  const toUserId = req.user.id;

  const fr = db.prepare("SELECT * FROM friend_requests WHERE fromUserId = ? AND toUserId = ? AND status = 'pending'").get(fromUserId, toUserId);
  if (!fr) return res.status(404).json({ error: 'Request not found' });

  try {
    db.prepare("UPDATE friend_requests SET status = 'accepted' WHERE fromUserId = ? AND toUserId = ?").run(fromUserId, toUserId);

    // Add friendship both ways
    db.prepare('INSERT OR IGNORE INTO friends (userId, friendId) VALUES (?, ?)').run(fromUserId, toUserId);
    db.prepare('INSERT OR IGNORE INTO friends (userId, friendId) VALUES (?, ?)').run(toUserId, fromUserId);

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


// reject
app.post('/api/friend/request/:id/reject', requireAuth, (req, res) => {
  const fromUserId = req.params.id;
  const toUserId = req.user.id;

  try {
    db.prepare("DELETE FROM friend_requests WHERE fromUserId = ? AND toUserId = ? AND status = 'pending'").run(fromUserId, toUserId);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


// GET all groups
app.get('/api/groups', requireAuth, (req, res) => {
  const groups = db.prepare('SELECT * FROM groups').all();
  res.json({ groups });
});

// join
app.post('/api/groups/join', requireAuth, (req, res) => {
  const groupId = req.body.groupId;
  const group = db.prepare('SELECT * FROM groups WHERE id = ?').get(groupId);
  if (!group) return res.status(404).json({ error: 'Group not found' });

  try {
    db.prepare('INSERT INTO group_members (groupId, userId) VALUES (?, ?)').run(groupId, req.user.id);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: 'Already joined', detail: e.message });
  }
});

// leave
app.post('/api/groups/leave', requireAuth, (req, res) => {
  const groupId = req.body.groupId;
  db.prepare('DELETE FROM group_members WHERE groupId = ? AND userId = ?').run(groupId, req.user.id);
  res.json({ success: true });
});

// get group mem
app.get('/api/groups/:id/members', requireAuth, (req, res) => {
  const groupId = req.params.id;

  // Check if group exists
  const group = db.prepare('SELECT * FROM groups WHERE id = ?').get(groupId);
  if (!group) return res.status(404).json({ error: 'Group not found' });

  // Fetch members
  const members = db.prepare(`
    SELECT u.id, u.username, u.email 
    FROM users u
    JOIN group_members gm ON u.id = gm.userId
    WHERE gm.groupId = ?
  `).all(groupId);

  res.json(members);
});


// cretae 1:1 chat
function getOrCreatePrivateChatGroup(userId1, userId2) {
  // Search for existing group with exactly these two members
  const group = db.prepare(`
    SELECT g.*
    FROM groups g
    JOIN group_members gm1 ON gm1.groupId = g.id AND gm1.userId = ?
    JOIN group_members gm2 ON gm2.groupId = g.id AND gm2.userId = ?
    GROUP BY g.id
    HAVING COUNT(*) = 2
  `).get(userId1, userId2);

  if (group) return group;

  // Create new private group for the two
  const id = 'g' + makeId(6);
  const name = `Chat_${userId1}_${userId2}`;
  db.prepare('INSERT INTO groups (id, name, destination) VALUES (?, ?, ?)').run(id, name, null);
  db.prepare('INSERT INTO group_members (groupId, userId) VALUES (?, ?)').run(id, userId1);
  db.prepare('INSERT INTO group_members (groupId, userId) VALUES (?, ?)').run(id, userId2);

  return db.prepare('SELECT * FROM groups WHERE id = ?').get(id);
}




// chat
app.post('/api/chat', requireAuth, (req, res) => {
  const { groupId, text } = req.body;
  if (!groupId || !text) return res.status(400).json({ error: 'Missing groupId or text' });

  // check membership
  const member = db.prepare('SELECT * FROM group_members WHERE groupId = ? AND userId = ?').get(groupId, req.user.id);
  if (!member) return res.status(403).json({ error: 'Not a member of group' });

  const id = 'c' + makeId(6);
  db.prepare('INSERT INTO chat_messages (id, groupId, userId, message, timestamp) VALUES (?, ?, ?, ?, ?)').run(
    id, groupId, req.user.id, text, Date.now()
  );
  res.json({ success: true, id });
});


// get msgs for group
app.get('/api/chat/:id', requireAuth, (req, res) => {
  const groupId = req.params.id;

  // Check if user is a member
  const isMember = db.prepare('SELECT 1 FROM group_members WHERE groupId = ? AND userId = ?')
    .get(groupId, req.user.id);
  if (!isMember) return res.status(403).json({ error: 'Not a member of this group' });

  const messages = db.prepare(`
    SELECT c.id, c.userId, u.username, c.message, c.timestamp
    FROM chat_messages c
    JOIN users u ON c.userId = u.id
    WHERE c.groupId = ?
    ORDER BY c.timestamp ASC
  `).all(groupId);

  res.json(messages);
});


// send msgs
app.get('/api/chat/:id', requireAuth, (req, res) => {
  const groupId = req.params.id;

  const isMember = db.prepare('SELECT 1 FROM group_members WHERE groupId = ? AND userId = ?')
    .get(groupId, req.user.id);
  if (!isMember) return res.status(403).json({ error: 'Not a member of this group' });

  const messages = db.prepare(`
    SELECT c.id, c.userId, u.username, c.message, c.timestamp
    FROM chat_messages c
    JOIN users u ON c.userId = u.id
    WHERE c.groupId = ?
    ORDER BY c.timestamp ASC
  `).all(groupId);

  res.json(messages);
});



// send message - supports group or friend chats by groupId or friendUsername
app.post('/api/chat/send', requireAuth, (req, res) => {
  const { groupId, message, friendUsername } = req.body;
  if (!message) return res.status(400).json({ error: 'Message cannot be empty' });

  let targetGroupId = groupId;

  if (!targetGroupId && friendUsername) {
    // Send direct message to friend via private chat group
    const friend = db.prepare('SELECT id FROM users WHERE username = ?').get(friendUsername);
    if (!friend) return res.status(404).json({ error: 'Friend not found' });

    // Check friendship
    const isFriend = db.prepare('SELECT 1 FROM friends WHERE userId = ? AND friendId = ?').get(req.user.id, friend.id);
    if (!isFriend) return res.status(403).json({ error: 'Not friends' });

    const group = getOrCreatePrivateChatGroup(req.user.id, friend.id);
    targetGroupId = group.id;
  }

  if (!targetGroupId) return res.status(400).json({ error: 'No target group or friend specified' });

  // Check membership
  const isMember = db.prepare('SELECT 1 FROM group_members WHERE groupId = ? AND userId = ?')
    .get(targetGroupId, req.user.id);
  if (!isMember) return res.status(403).json({ error: 'Not a member of this group' });

  const id = 'c' + makeId(6);
  const timestamp = Date.now();

  db.prepare('INSERT INTO chat_messages (id, groupId, userId, message, timestamp) VALUES (?, ?, ?, ?, ?)')
    .run(id, targetGroupId, req.user.id, message, timestamp);

  const msg = db.prepare(`
    SELECT c.id, c.userId, u.username, c.message, c.timestamp
    FROM chat_messages c
    JOIN users u ON c.userId = u.id
    WHERE c.id = ?
  `).get(id);

  res.json(msg);
});



// check auths 
app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username,
    role: req.user.role
  });
});



// check up
app.get('/api/health', (req, res) => res.json({ ok: true, env: process.env.NODE_ENV }));


// main()
app.listen(PORT, () => {
  console.log('VulnTour API Server running on', PORT);
});
