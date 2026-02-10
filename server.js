const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

// ===== DATABASE CONNECTION =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// ===== JWT SECRET =====
const JWT_SECRET = process.env.JWT_SECRET || 'trench-chat-secret-key-change-in-production';

// ===== POINTS CONFIG =====
const POINTS = {
  MESSAGE: 1,
  JOIN_NEW_ROOM: 5,
  FIRST_MESSAGE_IN_ROOM: 3,
  DAILY_LOGIN: 10,
  REACTION_RECEIVED: 2,
  VERIFIED_REFERRAL: 50
};

const DAILY_LIMITS = {
  MESSAGES: 100,
  NEW_ROOMS: 10,
  REACTIONS_RECEIVED: 50
};

const STREAK_POINTS = [
  5, 7, 9, 11, 14, 17, 20, 23, 26, 29,
  32, 35, 38, 41, 44, 45, 48, 51, 54, 58,
  62, 66, 70, 75, 80, 85, 90, 95, 100, 150
];

// ===== INITIALIZE DATABASE TABLES =====
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        avatar_url TEXT,
        bio TEXT,
        sol_wallet VARCHAR(44),
        referral_code VARCHAR(10) UNIQUE NOT NULL,
        referred_by INTEGER REFERENCES users(id),
        total_points INTEGER DEFAULT 0,
        daily_points INTEGER DEFAULT 0,
        daily_messages INTEGER DEFAULT 0,
        daily_rooms_joined INTEGER DEFAULT 0,
        daily_reactions_received INTEGER DEFAULT 0,
        last_points_reset DATE DEFAULT CURRENT_DATE,
        current_streak INTEGER DEFAULT 0,
        last_checkin DATE,
        longest_streak INTEGER DEFAULT 0,
        message_count INTEGER DEFAULT 0,
        rooms_messaged TEXT[] DEFAULT '{}',
        rooms_first_message TEXT[] DEFAULT '{}',
        is_verified BOOLEAN DEFAULT FALSE,
        last_message_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS referrals (
        id SERIAL PRIMARY KEY,
        referrer_id INTEGER REFERENCES users(id),
        referred_user_id INTEGER REFERENCES users(id),
        status VARCHAR(20) DEFAULT 'pending',
        points_awarded BOOLEAN DEFAULT FALSE,
        verified_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        room VARCHAR(100) NOT NULL,
        user_id INTEGER REFERENCES users(id),
        username VARCHAR(50) NOT NULL,
        text TEXT,
        image TEXT,
        reactions JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS chat_rooms (
        id SERIAL PRIMARY KEY,
        ca VARCHAR(100) UNIQUE NOT NULL,
        name VARCHAR(100),
        message_count INTEGER DEFAULT 0,
        user_count INTEGER DEFAULT 0,
        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS points_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        action VARCHAR(50) NOT NULL,
        points INTEGER NOT NULL,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room);
      CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
      CREATE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code);
      CREATE INDEX IF NOT EXISTS idx_users_points ON users(total_points DESC);
      CREATE INDEX IF NOT EXISTS idx_chat_rooms_activity ON chat_rooms(last_activity DESC);
    `);
    console.log("Database tables initialized");
  } catch (err) {
    console.error("Database init error:", err);
  } finally {
    client.release();
  }
}

initDB();

// ===== HELPER FUNCTIONS =====
function generateReferralCode() {
  return crypto.randomBytes(4).toString('hex').toUpperCase();
}

function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

async function checkDailyReset(userId) {
  const result = await pool.query(
    `SELECT last_points_reset FROM users WHERE id = $1`,
    [userId]
  );
  if (result.rows.length === 0) return;
  const lastReset = result.rows[0].last_points_reset;
  const today = new Date().toISOString().split('T')[0];
  if (lastReset !== today) {
    await pool.query(
      `UPDATE users SET 
        daily_points = 0, daily_messages = 0, daily_rooms_joined = 0,
        daily_reactions_received = 0, last_points_reset = CURRENT_DATE
       WHERE id = $1`,
      [userId]
    );
  }
}

async function awardPoints(userId, action, points, details = null) {
  await pool.query(
    `UPDATE users SET total_points = total_points + $1, daily_points = daily_points + $1 WHERE id = $2`,
    [points, userId]
  );
  await pool.query(
    `INSERT INTO points_log (user_id, action, points, details) VALUES ($1, $2, $3, $4)`,
    [userId, action, points, details]
  );
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ===== AUTH ENDPOINTS =====
app.post("/api/auth/register", async (req, res) => {
  const { username, email, password, referralCode } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }
  if (username.length < 3 || username.length > 20) {
    return res.status(400).json({ error: "Username must be 3-20 characters" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }
  try {
    const existing = await pool.query("SELECT id FROM users WHERE username = $1", [username.toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: "Username already taken" });
    }
    let referrerId = null;
    if (referralCode) {
      const referrer = await pool.query("SELECT id FROM users WHERE referral_code = $1", [referralCode.toUpperCase()]);
      if (referrer.rows.length > 0) referrerId = referrer.rows[0].id;
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const newReferralCode = generateReferralCode();
    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash, referral_code, referred_by)
       VALUES ($1, $2, $3, $4, $5) RETURNING id, username, referral_code, total_points, current_streak`,
      [username.toLowerCase(), email || null, passwordHash, newReferralCode, referrerId]
    );
    const user = result.rows[0];
    if (referrerId) {
      await pool.query(`INSERT INTO referrals (referrer_id, referred_user_id, status) VALUES ($1, $2, 'pending')`, [referrerId, user.id]);
    }
    const token = generateToken(user);
    res.json({ token, user: { id: user.id, username: user.username, referralCode: user.referral_code, total_points: user.total_points, current_streak: user.current_streak } });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }
  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [username.toLowerCase()]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    await checkDailyReset(user.id);
    const token = generateToken(user);
    res.json({
      token,
      user: {
        id: user.id, username: user.username, avatar_url: user.avatar_url, bio: user.bio,
        sol_wallet: user.sol_wallet, referralCode: user.referral_code, message_count: user.message_count,
        total_points: user.total_points, current_streak: user.current_streak, last_checkin: user.last_checkin, is_verified: user.is_verified
      }
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    await checkDailyReset(req.user.id);
    const result = await pool.query(
      `SELECT id, username, email, avatar_url, bio, sol_wallet, referral_code, 
              message_count, total_points, daily_points, current_streak, longest_streak,
              last_checkin, is_verified, created_at, daily_messages, daily_rooms_joined, daily_reactions_received
       FROM users WHERE id = $1`,
      [req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error("Get user error:", err);
    res.status(500).json({ error: "Failed to get user" });
  }
});

// ===== STREAK ENDPOINTS =====
app.post("/api/checkin", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`SELECT current_streak, last_checkin, longest_streak FROM users WHERE id = $1`, [req.user.id]);
    const user = result.rows[0];
    const today = new Date().toISOString().split('T')[0];
    const lastCheckin = user.last_checkin ? new Date(user.last_checkin).toISOString().split('T')[0] : null;
    if (lastCheckin === today) {
      return res.status(400).json({ error: "Already checked in today", nextCheckin: getNextCheckinTime() });
    }
    let newStreak = 1;
    if (lastCheckin) {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      const yesterdayStr = yesterday.toISOString().split('T')[0];
      if (lastCheckin === yesterdayStr) {
        newStreak = user.current_streak + 1;
        if (newStreak > 30) newStreak = 1;
      }
    }
    const streakIndex = Math.min(newStreak - 1, 29);
    const points = STREAK_POINTS[streakIndex];
    const longestStreak = Math.max(user.longest_streak || 0, newStreak);
    await pool.query(
      `UPDATE users SET current_streak = $1, last_checkin = CURRENT_DATE, longest_streak = $2, total_points = total_points + $3 WHERE id = $4`,
      [newStreak, longestStreak, points, req.user.id]
    );
    await pool.query(`INSERT INTO points_log (user_id, action, points, details) VALUES ($1, $2, $3, $4)`, [req.user.id, 'DAILY_CHECKIN', points, `Day ${newStreak} streak`]);
    res.json({ success: true, streak: newStreak, pointsEarned: points, longestStreak, nextCheckin: getNextCheckinTime() });
  } catch (err) {
    console.error("Checkin error:", err);
    res.status(500).json({ error: "Check-in failed" });
  }
});

function getNextCheckinTime() {
  const now = new Date();
  const tomorrow = new Date(now);
  tomorrow.setDate(tomorrow.getDate() + 1);
  tomorrow.setHours(0, 0, 0, 0);
  return tomorrow.toISOString();
}

app.get("/api/streak", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`SELECT current_streak, last_checkin, longest_streak FROM users WHERE id = $1`, [req.user.id]);
    const user = result.rows[0];
    const today = new Date().toISOString().split('T')[0];
    const lastCheckin = user.last_checkin ? new Date(user.last_checkin).toISOString().split('T')[0] : null;
    let currentStreak = user.current_streak;
    let canCheckin = true;
    if (lastCheckin === today) {
      canCheckin = false;
    } else if (lastCheckin) {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      const yesterdayStr = yesterday.toISOString().split('T')[0];
      if (lastCheckin !== yesterdayStr) currentStreak = 0;
    }
    const nextStreakDay = currentStreak >= 30 ? 1 : currentStreak + 1;
    const nextPoints = STREAK_POINTS[Math.min(nextStreakDay - 1, 29)];
    res.json({ currentStreak, longestStreak: user.longest_streak || 0, lastCheckin: user.last_checkin, canCheckin, nextCheckin: canCheckin ? null : getNextCheckinTime(), nextPoints, streakPoints: STREAK_POINTS });
  } catch (err) {
    console.error("Get streak error:", err);
    res.status(500).json({ error: "Failed to get streak" });
  }
});

// ===== POINTS ENDPOINTS =====
app.get("/api/points", authMiddleware, async (req, res) => {
  try {
    await checkDailyReset(req.user.id);
    const user = await pool.query(`SELECT total_points, daily_points, daily_messages, daily_rooms_joined, daily_reactions_received FROM users WHERE id = $1`, [req.user.id]);
    const history = await pool.query(`SELECT action, points, details, created_at FROM points_log WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`, [req.user.id]);
    res.json({
      totalPoints: user.rows[0].total_points, dailyPoints: user.rows[0].daily_points,
      dailyLimits: {
        messages: { used: user.rows[0].daily_messages, max: DAILY_LIMITS.MESSAGES },
        rooms: { used: user.rows[0].daily_rooms_joined, max: DAILY_LIMITS.NEW_ROOMS },
        reactions: { used: user.rows[0].daily_reactions_received, max: DAILY_LIMITS.REACTIONS_RECEIVED }
      },
      history: history.rows, pointsConfig: POINTS
    });
  } catch (err) {
    console.error("Get points error:", err);
    res.status(500).json({ error: "Failed to get points" });
  }
});

app.get("/api/leaderboard", async (req, res) => {
  try {
    const pointsLb = await pool.query(`SELECT username, avatar_url, total_points, current_streak FROM users WHERE total_points > 0 ORDER BY total_points DESC LIMIT 200`);
    const referralsLb = await pool.query(`SELECT u.username, u.avatar_url, COUNT(r.id) as referral_count FROM users u LEFT JOIN referrals r ON r.referrer_id = u.id AND r.status = 'verified' GROUP BY u.id HAVING COUNT(r.id) > 0 ORDER BY referral_count DESC LIMIT 200`);
    res.json({ pointsLeaderboard: pointsLb.rows, referralsLeaderboard: referralsLb.rows });
  } catch (err) {
    console.error("Leaderboard error:", err);
    res.status(500).json({ error: "Failed to get leaderboard" });
  }
});

// ===== PROFILE ENDPOINTS =====
app.put("/api/profile", authMiddleware, async (req, res) => {
  const { avatar_url, bio, sol_wallet } = req.body;
  try {
    const result = await pool.query(
      `UPDATE users SET avatar_url = COALESCE($1, avatar_url), bio = COALESCE($2, bio), sol_wallet = COALESCE($3, sol_wallet) WHERE id = $4
       RETURNING id, username, avatar_url, bio, sol_wallet, referral_code, message_count, total_points, current_streak, is_verified`,
      [avatar_url, bio, sol_wallet, req.user.id]
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error("Update profile error:", err);
    res.status(500).json({ error: "Failed to update profile" });
  }
});

app.get("/api/profile/:username", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, avatar_url, bio, message_count, total_points, current_streak, longest_streak, is_verified, created_at FROM users WHERE username = $1`,
      [req.params.username.toLowerCase()]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });
    const refCount = await pool.query(`SELECT COUNT(*) as count FROM referrals WHERE referrer_id = $1 AND status = 'verified'`, [result.rows[0].id]);
    res.json({ user: { ...result.rows[0], referral_count: parseInt(refCount.rows[0].count) } });
  } catch (err) {
    console.error("Get profile error:", err);
    res.status(500).json({ error: "Failed to get profile" });
  }
});

// ===== REFERRAL ENDPOINTS =====
app.get("/api/referrals", authMiddleware, async (req, res) => {
  try {
    const user = await pool.query("SELECT referral_code FROM users WHERE id = $1", [req.user.id]);
    const stats = await pool.query(`SELECT COUNT(*) FILTER (WHERE status = 'pending') as pending, COUNT(*) FILTER (WHERE status = 'verified') as verified FROM referrals WHERE referrer_id = $1`, [req.user.id]);
    const referrals = await pool.query(`SELECT u.username, u.avatar_url, r.status, r.created_at, r.verified_at FROM referrals r JOIN users u ON u.id = r.referred_user_id WHERE r.referrer_id = $1 ORDER BY r.created_at DESC LIMIT 50`, [req.user.id]);
    res.json({ referralCode: user.rows[0].referral_code, stats: { pending: parseInt(stats.rows[0].pending), verified: parseInt(stats.rows[0].verified) }, referrals: referrals.rows });
  } catch (err) {
    console.error("Get referrals error:", err);
    res.status(500).json({ error: "Failed to get referrals" });
  }
});

app.get("/api/referrals/leaderboard", async (req, res) => {
  try {
    const result = await pool.query(`SELECT u.username, u.avatar_url, COUNT(r.id) as referral_count FROM users u LEFT JOIN referrals r ON r.referrer_id = u.id AND r.status = 'verified' GROUP BY u.id HAVING COUNT(r.id) > 0 ORDER BY referral_count DESC LIMIT 200`);
    res.json({ leaderboard: result.rows });
  } catch (err) {
    console.error("Leaderboard error:", err);
    res.status(500).json({ error: "Failed to get leaderboard" });
  }
});

// ===== DISCOVER ENDPOINTS =====
app.get("/api/discover/rooms", async (req, res) => {
  try {
    const result = await pool.query(`SELECT ca, name, message_count, user_count, last_activity FROM chat_rooms ORDER BY last_activity DESC LIMIT 50`);
    res.json({ rooms: result.rows });
  } catch (err) {
    console.error("Get rooms error:", err);
    res.status(500).json({ error: "Failed to get rooms" });
  }
});

app.get("/api/discover/search", async (req, res) => {
  const { q } = req.query;
  if (!q) return res.json({ rooms: [] });
  try {
    const result = await pool.query(`SELECT ca, name, message_count, user_count, last_activity FROM chat_rooms WHERE ca ILIKE $1 OR name ILIKE $1 ORDER BY message_count DESC LIMIT 20`, [`%${q}%`]);
    res.json({ rooms: result.rows });
  } catch (err) {
    console.error("Search rooms error:", err);
    res.status(500).json({ error: "Failed to search rooms" });
  }
});

// ===== SOCKET.IO FOR CHAT =====
io.on("connection", (socket) => {
  console.log("User connected:", socket.id);
  let currentUserId = null;
  let currentUsername = null;

  socket.on("authenticate", async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      currentUserId = decoded.id;
      currentUsername = decoded.username;
      socket.userId = decoded.id;
      socket.username = decoded.username;
      await checkDailyReset(currentUserId);
      console.log("Socket authenticated:", decoded.username);
    } catch (err) {
      console.log("Socket auth failed");
    }
  });

  socket.on("join_room", async (ca) => {
    socket.join(ca);
    console.log(`Socket ${socket.id} joined room ${ca}`);
    try {
      await pool.query(`INSERT INTO chat_rooms (ca, last_activity) VALUES ($1, CURRENT_TIMESTAMP) ON CONFLICT (ca) DO UPDATE SET last_activity = CURRENT_TIMESTAMP`, [ca]);
      if (currentUserId) {
        const userRooms = await pool.query(`SELECT rooms_messaged FROM users WHERE id = $1`, [currentUserId]);
        const rooms = userRooms.rows[0].rooms_messaged || [];
        if (!rooms.includes(ca)) {
          const limits = await pool.query(`SELECT daily_rooms_joined FROM users WHERE id = $1`, [currentUserId]);
          if (limits.rows[0].daily_rooms_joined < DAILY_LIMITS.NEW_ROOMS) {
            await awardPoints(currentUserId, 'JOIN_NEW_ROOM', POINTS.JOIN_NEW_ROOM, ca);
            await pool.query(`UPDATE users SET daily_rooms_joined = daily_rooms_joined + 1 WHERE id = $1`, [currentUserId]);
          }
        }
      }
      const result = await pool.query(`SELECT id, username, text, image, reactions, created_at as time FROM messages WHERE room = $1 ORDER BY created_at DESC LIMIT 50`, [ca]);
      const messages = result.rows.reverse().map(m => ({ id: m.id.toString(), user: m.username, text: m.text, image: m.image, reactions: m.reactions || {}, time: new Date(m.time).getTime() }));
      socket.emit("chat_history", messages);
    } catch (err) {
      console.error("Join room error:", err);
      socket.emit("chat_history", []);
    }
  });

  socket.on("send_message", async ({ room, message }) => {
    let canEarnPoints = true;
    if (currentUserId) {
      const lastMsg = await pool.query(`SELECT last_message_at FROM users WHERE id = $1`, [currentUserId]);
      if (lastMsg.rows[0].last_message_at) {
        const timeDiff = Date.now() - new Date(lastMsg.rows[0].last_message_at).getTime();
        if (timeDiff < 10000) canEarnPoints = false;
      }
      if (!message.text || message.text.trim().length < 3) canEarnPoints = false;
    }
    const msgData = { id: Date.now().toString(), user: message.user, text: message.text || null, image: message.image || null, reactions: {}, time: Date.now() };
    try {
      const result = await pool.query(`INSERT INTO messages (room, user_id, username, text, image) VALUES ($1, $2, $3, $4, $5) RETURNING id`, [room, currentUserId || null, message.user, message.text || null, message.image || null]);
      msgData.id = result.rows[0].id.toString();
      await pool.query(`UPDATE chat_rooms SET message_count = message_count + 1, last_activity = CURRENT_TIMESTAMP WHERE ca = $1`, [room]);
      if (currentUserId) {
        const userCheck = await pool.query(`SELECT rooms_messaged, rooms_first_message, daily_messages FROM users WHERE id = $1`, [currentUserId]);
        const userData = userCheck.rows[0];
        const isNewRoom = !userData.rooms_messaged.includes(room);
        const isFirstMessage = !userData.rooms_first_message.includes(room);
        let updateQuery = `UPDATE users SET message_count = message_count + 1, last_message_at = CURRENT_TIMESTAMP`;
        if (isNewRoom) updateQuery += `, rooms_messaged = array_append(rooms_messaged, '${room}')`;
        if (isFirstMessage) updateQuery += `, rooms_first_message = array_append(rooms_first_message, '${room}')`;
        updateQuery += ` WHERE id = ${currentUserId}`;
        await pool.query(updateQuery);
        if (canEarnPoints && userData.daily_messages < DAILY_LIMITS.MESSAGES) {
          await awardPoints(currentUserId, 'MESSAGE', POINTS.MESSAGE, room);
          await pool.query(`UPDATE users SET daily_messages = daily_messages + 1 WHERE id = $1`, [currentUserId]);
          if (isFirstMessage) await awardPoints(currentUserId, 'FIRST_MESSAGE_IN_ROOM', POINTS.FIRST_MESSAGE_IN_ROOM, room);
        }
        const verifyCheck = await pool.query(`SELECT message_count, array_length(rooms_messaged, 1) as room_count, is_verified FROM users WHERE id = $1`, [currentUserId]);
        const verifyData = verifyCheck.rows[0];
        if (!verifyData.is_verified && verifyData.message_count >= 5 && verifyData.room_count >= 2) {
          await pool.query(`UPDATE users SET is_verified = TRUE WHERE id = $1`, [currentUserId]);
          const refResult = await pool.query(`UPDATE referrals SET status = 'verified', verified_at = CURRENT_TIMESTAMP WHERE referred_user_id = $1 AND status = 'pending' RETURNING referrer_id`, [currentUserId]);
          if (refResult.rows.length > 0) {
            await awardPoints(refResult.rows[0].referrer_id, 'VERIFIED_REFERRAL', POINTS.VERIFIED_REFERRAL, currentUsername);
          }
        }
      }
    } catch (err) {
      console.error("Save message error:", err);
    }
    io.to(room).emit("receive_message", msgData);
  });

  socket.on("add_reaction", async ({ room, msgId, emoji, user }) => {
    try {
      const result = await pool.query(`SELECT reactions, user_id FROM messages WHERE id = $1`, [msgId]);
      if (result.rows.length === 0) return;
      let reactions = result.rows[0].reactions || {};
      const msgOwnerId = result.rows[0].user_id;
      if (!reactions[emoji]) reactions[emoji] = [];
      const userIndex = reactions[emoji].indexOf(user);
      const isAdding = userIndex === -1;
      if (isAdding) {
        reactions[emoji].push(user);
        if (msgOwnerId && msgOwnerId !== currentUserId) {
          const ownerLimits = await pool.query(`SELECT daily_reactions_received FROM users WHERE id = $1`, [msgOwnerId]);
          if (ownerLimits.rows[0].daily_reactions_received < DAILY_LIMITS.REACTIONS_RECEIVED) {
            await awardPoints(msgOwnerId, 'REACTION_RECEIVED', POINTS.REACTION_RECEIVED, emoji);
            await pool.query(`UPDATE users SET daily_reactions_received = daily_reactions_received + 1 WHERE id = $1`, [msgOwnerId]);
          }
        }
      } else {
        reactions[emoji].splice(userIndex, 1);
        if (reactions[emoji].length === 0) delete reactions[emoji];
      }
      await pool.query(`UPDATE messages SET reactions = $1 WHERE id = $2`, [JSON.stringify(reactions), msgId]);
      io.to(room).emit("reaction_update", { msgId, reactions });
    } catch (err) {
      console.error("Reaction error:", err);
    }
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

app.get("/", (req, res) => {
  res.send("Trench Chat Server v2.0 - With Auth, Points & Streaks");
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});