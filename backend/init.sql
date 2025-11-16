PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  email TEXT,
  role TEXT NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS tours (
  id TEXT PRIMARY KEY,
  title TEXT,
  price INTEGER,
  ownerId TEXT,
  groupId TEXT,
  FOREIGN KEY(ownerId) REFERENCES users(id),
  FOREIGN KEY(groupId) REFERENCES groups(id)
);


CREATE TABLE IF NOT EXISTS friends (
  userId TEXT,
  friendId TEXT,
  UNIQUE(userId, friendId),
  FOREIGN KEY(userId) REFERENCES users(id),
  FOREIGN KEY(friendId) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS groups (
  id TEXT PRIMARY KEY,
  name TEXT,
  destination TEXT
);

CREATE TABLE IF NOT EXISTS group_members (
  groupId TEXT,
  userId TEXT,
  UNIQUE(groupId, userId),
  FOREIGN KEY(groupId) REFERENCES groups(id),
  FOREIGN KEY(userId) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS chat_messages (
  id TEXT PRIMARY KEY,
  groupId TEXT,
  userId TEXT,
  message TEXT,
  timestamp INTEGER,
  FOREIGN KEY(groupId) REFERENCES groups(id),
  FOREIGN KEY(userId) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS tour_joins (
  tourId TEXT,
  userId TEXT,
  UNIQUE(tourId, userId),
  FOREIGN KEY(tourId) REFERENCES tours(id),
  FOREIGN KEY(userId) REFERENCES users(id)
);


CREATE TABLE IF NOT EXISTS friend_requests (
  fromUserId TEXT,
  toUserId TEXT,
  status TEXT, -- e.g., 'pending', 'accepted', etc.
  UNIQUE(fromUserId, toUserId),
  FOREIGN KEY(fromUserId) REFERENCES users(id),
  FOREIGN KEY(toUserId) REFERENCES users(id)
);


-- admin:admin
INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES ('u1','admin','$2b$12$scBvx15erY2hSoVY8GKEiOzkffyR/8j8KINYAF7V5HFT7KOrRANPO','admin@example.com','admin'),('u2','test','$2b$12$qECCOyJ08psu58yy3KOtkuPZGzq.KwgcFDhI0V4.Ay35XGYZzfSQ6','test@example.com','user');