/**
 * 
 * 
 * [VulnTour]
 *    Vulnerable Node.js implementation + Express API (SQLite)
 * 
 *     /backend
 *          -  server.js contains the API endpoints required by the site to work efficiently
 *          -  init.sql contains the sqlite queries 
 *          -  Dockerfile  contains the instruction for the docker-compose file
 * 
 * 
 *     NOTE:
 *          - Incase of running it without using Docker, your system should have "Node 20"
 *          - "libsqlite3-dev" package is required for better-sqlite3   [apt install libsqlite3-dev -y] (linux)
 * 
 * 
 * 
 * 
 * WARNING: Unsafe code. Run in lab environments only.
 * 
 * [Run]
 *    - docker-compose up -d --build
 *    - docker-compose down
 * 
 * 
 * 
 * just a playground to pentest with modern frameworks :) 
 * 
 * 
 * 
 * [Vulnerabilities]
 * 
 * APIs
 *  - mass assignment
 *  - bola
 * 
 * 
 * JWT
 *  - weak secret key
 *  - algorithm confusion attack
 *  - sensitive data exposure
 *  - idor
 * 
 * 
 * To add Business Flaws and oauth implementation flaws
 * 
 * 
 * 
 * [NOTE] CONTRIBUTIONS are welcome just add some bugs which got medium - high severity in the market 
 * 
 * 
 * @debang5hu
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

// store pass $12$
const saltRounds = 12;

// db setup
const DB_FILE = process.env.DB_FILE || 'database.sqlite3';
const isNew = !fs.existsSync(DB_FILE);
const db = new Database(DB_FILE);

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'mychemicalromance';  // weak secret key  [hardcode shit tho]

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
  max: 100,   // 60
  standardHeaders: true,
  legacyHeaders: false
});

app.use(limiter);  // init rate limit


// CORS config
const rawOrigins = process.env.CORS_ORIGINS || 'http://localhost:3000, http://127.0.0.1, http://localhost';
const allowedOrigins = rawOrigins.split(',').map(s => s.trim()).filter(Boolean);

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
        //console.log('[CORS] Allowed:', origin); 
        return callback(null, true);
    }

    console.warn('Blocked CORS origin:', origin);
    return callback(null, false);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Requested-With'],
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions)); // init cors
app.options('*', cors(corsOptions));  // browser preflight



/*                        helper funcs */

// id
function makeId(prefix = 'id', lenBytes = 8) {
  return prefix + crypto.randomBytes(lenBytes).toString('hex');
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET);
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);  // does not enforce algorithms strictly (algorithm confusion attack) 
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


/**                                  
 *                          API endpoints 
 * 
 * 
 * 
 *   [Account Creation]
 * 
 *   POST /api/register 
 *   POST /api/login
 *   
*/




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


/**
 * 
 * [User Account]
 * 
 * GET      /api/users
 * POST     /api/users/:id
 * PUT      /api/users/:id
 * DELETE   /api/users/:id
 * 
 */


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




/**
 * 
 * [Tours]
 * 
 * GET      /api/tours
 * POST     /api/tours
 * PUT      /api/tours/:id
 * DELETE   /api/tours/:id
 * 
 * 
 * POST     /api/tours/:id/join
 * GET      /api/tours/joined
 * POST     /api/tours/:id/notify-creator
 * 
 * 
 * 
 */


app.get('/api/tours', requireAuth, (req, res) => {
  try {
    const tours = db.prepare(`
      SELECT t.*, u.username AS ownerUsername
      FROM tours t
      JOIN users u ON t.ownerId = u.id
    `).all();

    res.json(tours);

  } catch (err) {
    console.error("Error loading tours:", err);
    res.status(500).json({ error: "Failed to load tours" });
  }
});

app.post('/api/tours', requireAuth, (req, res) => {
  const id = 't' + makeId(6);
  const ownerId = req.user && req.user.id;
  const { title, price = 0, location = 'Unknown', duration = 0, description = '' } = req.body;
  const groupId = 'g' + makeId(6);

  try {
    // Create group
    db.prepare('INSERT INTO groups (id, name, destination) VALUES (?, ?, ?)').run(groupId, title, location);
    
    // Create tour
    db.prepare(`INSERT INTO tours 
      (id, title, price, ownerId, groupId, location, duration, description) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id, title, price, ownerId, groupId, location, duration, description);

    // auto join (did not worked tho)
    //db.prepare('INSERT INTO group_members (groupId, userId) VALUES (?, ?)').run(groupId, ownerId);

    const tour = db.prepare('SELECT * FROM tours WHERE id = ?').get(id);
    res.json(tour);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});




app.put('tours/:id', requireAuth, (req, res) => {
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
  try {
    const tour = db.prepare('SELECT * FROM tours WHERE id = ?').get(req.params.id);
    if (!tour) return res.status(404).json({ error: 'Tour not found' });
    if (tour.ownerId !== req.user.id) return res.status(403).json({ error: 'Not owner' });

    // Delete related tour joins first
    db.prepare('DELETE FROM tour_joins WHERE tourId = ?').run(tour.id);

    if (tour.groupId) {
      db.prepare('DELETE FROM group_members WHERE groupId = ?').run(tour.groupId);
      db.prepare('DELETE FROM groups WHERE id = ?').run(tour.groupId);
    }

    // Delete the tour itself
    db.prepare('DELETE FROM tours WHERE id = ?').run(tour.id);

    res.json({ success: true });

  } catch (e) {
    console.error('Error deleting tour:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.post('/api/tours/:id/join', requireAuth, (req, res) => {
  const tourId = req.params.id;
  const userId = req.user.id;

  const tour = db.prepare('SELECT * FROM tours WHERE id = ?').get(tourId);
  if (!tour) return res.status(404).json({ error: 'Tour not found' });

  try {
    // Check if already joined
    const existing = db.prepare('SELECT 1 FROM tour_joins WHERE tourId = ? AND userId = ?').get(tourId, userId);
    if (existing) {
      return res.json({ success: true, message: 'Already joined' });
    }

    db.prepare('INSERT INTO tour_joins (tourId, userId) VALUES (?, ?)').run(tourId, userId);

    if (tour.groupId) {
      db.prepare('INSERT OR IGNORE INTO group_members (groupId, userId) VALUES (?, ?)').run(tour.groupId, userId);
    }

    res.json({ success: true, tourId });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});



app.get('/api/tours/joined', requireAuth, (req, res) => {
  const userId = req.user.id;
  const joinedTours = db.prepare(`
    SELECT t.*
    FROM tours t
    JOIN tour_joins tj ON t.id = tj.tourId
    WHERE tj.userId = ?
  `).all(userId);

  res.json(joinedTours);
});


app.post('/api/tours/:id/notify-creator', requireAuth, (req, res) => {
  const tourId = req.params.id;
  // Lookup tour and owner
  const tour = db.prepare('SELECT * FROM tours WHERE id = ?').get(tourId);
  if (!tour) return res.status(404).json({ error: 'Tour not found' });

  console.log(`[Notify] User ${req.user.username} joined tour ${tour.title}. Notify owner: ${tour.ownerId}`);

  res.json({ ok: true, notified: tour.ownerId });
});


/**
 * 
 * [Admin Config]
 * 
 * leads to RCE [abuse eval()]
 * 
 * POST     /api/admin/query
 * 
 */

app.post('/api/admin/query', requireAuth, requireAdmin, (req, res) => {
  const q = req.body.q;
  try {
    const result = eval(q);   // rce
    res.json({ ok: true, result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});



/**
 * [Friend]
 * 
 * 
 * GET        /api/friend
 * POST       /api/friend
 * DELETE     /api/friend/:username
 * 
 * GET        /api/friend/request
 * POST       /api/friend/request
 * 
 * POST       /api/friend/request/:id/accept
 * POST       /api/friend/request/:id/reject
 * 
 * 
 */


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


/**
 * 
 * [Groups]
 * 
 * GET        /api/groups
 * POST       /api/groups/join
 * 
 * 
 * POST       /api/groups/leave
 * 
 * GET        /api/groups/:id/members
 * 
 * 
 */


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

// list groups the user belongs to
app.get('/api/groups/joined', requireAuth, (req, res) => {
  const groups = db.prepare(
    `SELECT g.* FROM groups g
     JOIN group_members gm ON g.id = gm.groupId
     WHERE gm.userId = ?`
  ).all(req.user.id);
  res.json({ groups });
});

// leave
app.post('/api/groups/leave', requireAuth, (req, res) => {
  const groupId = req.body.groupId;
  const userId = req.user.id;

  try {
    const tour = db.prepare('SELECT * FROM tours WHERE groupId = ?').get(groupId);
    if (!tour) return res.status(404).json({ error: 'Group not linked to a tour' });

    db.prepare('DELETE FROM group_members WHERE groupId = ? AND userId = ?').run(groupId, userId);

    db.prepare('DELETE FROM tour_joins WHERE tourId = ? AND userId = ?').run(tour.id, userId);

    res.json({ success: true });
  } catch (err) {
    console.error('Error leaving group:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
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


/**
 * 
 * [Chat]
 * 
 * POST   /api/chat
 * GET    /api/chat/:id
 * 
 */

// chat
app.post('/api/chat', requireAuth, (req, res) => {
  const { groupId, message } = req.body;

  if (!groupId || !message) {
    return res.status(400).json({ error: 'groupId and message are required' });
  }

  const isMember = db.prepare('SELECT 1 FROM group_members WHERE groupId = ? AND userId = ?').get(groupId, req.user.id);
  if (!isMember) return res.status(403).json({ error: 'Not a member of this group' });

  const id = 'c' + makeId(6);
  const timestamp = Date.now();

  db.prepare('INSERT INTO chat_messages (id, groupId, userId, message, timestamp) VALUES (?, ?, ?, ?, ?)')
    .run(id, groupId, req.user.id, message, timestamp);

  const msg = db.prepare(`
    SELECT c.id, c.userId, u.username, c.message, c.timestamp
    FROM chat_messages c
    JOIN users u ON c.userId = u.id
    WHERE c.id = ?
  `).get(id);

  res.json(msg);
});



// get msgs for group
app.get('/api/chat/:id', requireAuth, (req, res) => {
  const groupId = req.params.id;

  // check if user is a member
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


/**
 * [TO DO]
 * 
 * - open redirect  (oauth implemetation flaw)
 * - 
 * 
 */

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




/**
 *  Authenticates
 */

app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username,
    role: req.user.role
  });
});


// check up
app.get('/api/health', (req, res) => res.json({ ok: true, env: process.env.NODE_ENV }));


// 0.0.0.0:PORT
app.listen(PORT, () => {
  console.log('VulnTour API Server running on', PORT);
});

