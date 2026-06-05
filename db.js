const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'data.db');
let db = null;

async function getDb() {
  if (db) return db;
  const SQL = await initSqlJs({locateFile: file => path.join(__dirname, 'public', file)});
  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }
  db.run('PRAGMA journal_mode=WAL');
  initSchema();
  return db;
}

function saveDb() {
  if (!db) return;
  const data = db.export();
  const buf = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buf);
}

function initSchema() {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, avatar TEXT DEFAULT '', school TEXT DEFAULT '', major TEXT DEFAULT '', bio TEXT DEFAULT '', coins INTEGER DEFAULT 30, password_hash TEXT DEFAULT '', created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS follows (follower_id TEXT NOT NULL, following_id TEXT NOT NULL, PRIMARY KEY (follower_id, following_id));
    CREATE TABLE IF NOT EXISTS circles (id TEXT PRIMARY KEY, name TEXT NOT NULL, emoji TEXT DEFAULT '🌟', description TEXT DEFAULT '', owner_id TEXT NOT NULL, notice TEXT DEFAULT '', rules TEXT DEFAULT '[]', created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS circle_members (circle_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (circle_id, user_id));
    CREATE TABLE IF NOT EXISTS posts (id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT DEFAULT '', author_id TEXT NOT NULL, circle_id TEXT DEFAULT 'c_hall', board TEXT DEFAULT '全部', tags TEXT DEFAULT '[]', images TEXT DEFAULT '[]', anon INTEGER DEFAULT 0, essence INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now')), views INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS post_likes (post_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (post_id, user_id));
    CREATE TABLE IF NOT EXISTS post_collects (post_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (post_id, user_id));
    CREATE TABLE IF NOT EXISTS post_coins (post_id TEXT NOT NULL, user_id TEXT NOT NULL, amount INTEGER DEFAULT 1, PRIMARY KEY (post_id, user_id));
    CREATE TABLE IF NOT EXISTS comments (id TEXT PRIMARY KEY, post_id TEXT NOT NULL, user_id TEXT NOT NULL, text TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS comment_likes (comment_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (comment_id, user_id));
    CREATE TABLE IF NOT EXISTS replies (id TEXT PRIMARY KEY, comment_id TEXT NOT NULL, user_id TEXT NOT NULL, text TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT NOT NULL, text TEXT DEFAULT '', img TEXT DEFAULT '', read INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS notifications (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, title TEXT NOT NULL, icon TEXT DEFAULT '', type TEXT DEFAULT '', post_id TEXT DEFAULT '', read INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, post_id TEXT NOT NULL, reason TEXT NOT NULL, reporter_id TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS daily_signins (user_id TEXT NOT NULL, date TEXT NOT NULL, PRIMARY KEY (user_id, date));
        CREATE TABLE IF NOT EXISTS sync_state (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE IF NOT EXISTS user_data (user_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT, PRIMARY KEY (user_id, key));
    CREATE TABLE IF NOT EXISTS search_history (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, query TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')));
  `);
  saveDb();
}

module.exports = { getDb, saveDb };
