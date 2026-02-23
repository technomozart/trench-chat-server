const { Pool } = require('pg');
const p = new Pool({ connectionString: 'postgresql://postgres:QXqdWMBhBBeWMvpDxLgmgPrhdPxDDqxO@shuttle.proxy.rlwy.net:44709/railway', ssl: { rejectUnauthorized: false } });

async function fix() {
  const columns = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN DEFAULT FALSE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS muted_rooms TEXT[] DEFAULT '{}'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS rooms_messaged TEXT[] DEFAULT '{}'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS rooms_first_message TEXT[] DEFAULT '{}'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_message_at TIMESTAMP",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS daily_messages INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS daily_rooms_joined INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS daily_reactions_received INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_points_reset DATE DEFAULT CURRENT_DATE",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS daily_points INTEGER DEFAULT 0",
    "CREATE TABLE IF NOT EXISTS moderation_log (id SERIAL PRIMARY KEY, admin_id INTEGER REFERENCES users(id), target_user_id INTEGER REFERENCES users(id), action VARCHAR(50) NOT NULL, room VARCHAR(255), reason TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
  ];

  for (const sql of columns) {
    try {
      await p.query(sql);
      console.log("OK:", sql.substring(0, 60) + "...");
    } catch (err) {
      console.log("SKIP:", err.message.substring(0, 80));
    }
  }

  // Verify
  const r = await p.query("SELECT username, is_admin, is_blocked, rooms_messaged, last_message_at FROM users LIMIT 5");
  console.log("\nUsers:", r.rows);

  await p.end();
  console.log("\nDone! All columns added.");
}

fix();
