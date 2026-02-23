const { Pool } = require('pg');
const p = new Pool({ connectionString: 'postgresql://postgres:QXqdWMBhBBeWMvpDxLgmgPrhdPxDDqxO@shuttle.proxy.rlwy.net:44709/railway', ssl: { rejectUnauthorized: false } });

async function run() {
  await p.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE");
  await p.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN DEFAULT FALSE");
  await p.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS muted_rooms TEXT[] DEFAULT '{}'");
  await p.query("UPDATE users SET is_admin = true WHERE LOWER(username) = 'technomozart'");
  const r = await p.query("SELECT username, is_admin FROM users WHERE is_admin = true");
  console.log(r.rows);
  await p.end();
}

run();