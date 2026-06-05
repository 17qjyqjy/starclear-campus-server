const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const { getDb, saveDb } = require('./db');

const app = express();
const JWT_SECRET = 'starclear-campus-secret-key-2024';
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use('/uploads', express.static('uploads'));
app.use(express.static(path.join(__dirname, 'public')));

// --- Auth middleware ---
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '未登录' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { return res.status(401).json({ error: 'token 失效' }); }
}

function optionalAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (token) { try { req.user = jwt.verify(token, JWT_SECRET); } catch {} }
  next();
}

// --- User ---
app.post('/api/auth/register', async (req, res) => {
  const db = await getDb();
  const { name, password, school, major, bio } = req.body;
  if (!name || !password) return res.status(400).json({ error: '昵称和密码必填' });
  const hash = bcrypt.hashSync(password, 10);
  const id = 'u_' + uuidv4().slice(0, 8);
  const avatar = `https://api.dicebear.com/7.x/thumbs/svg?seed=${encodeURIComponent(name)}`;
  db.run('INSERT INTO users (id, name, avatar, school, major, bio, password_hash) VALUES (?,?,?,?,?,?,?)', [id, name, avatar, school || '', major || '', bio || '', hash]);
  saveDb();
  const token = jwt.sign({ id, name }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id, name, avatar, school: school || '', major: major || '', bio: bio || '', coins: 30 } });
});

app.post('/api/auth/login', async (req, res) => {
  const db = await getDb();
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: '昵称和密码必填' });
  const user = db.exec('SELECT * FROM users WHERE name = ?', [name])[0]?.values[0];
  if (!user) return res.status(400).json({ error: '用户不存在' });
  const cols = db.exec('PRAGMA table_info(users)')[0].values.map(c => c[1]);
  const u = Object.fromEntries(cols.map((c, i) => [c, user[i]]));
  if (!bcrypt.compareSync(password, u.password_hash)) return res.status(400).json({ error: '密码错误' });
  const token = jwt.sign({ id: u.id, name: u.name }, JWT_SECRET, { expiresIn: '7d' });
  const following = db.exec('SELECT following_id FROM follows WHERE follower_id = ?', [u.id])[0]?.values.map(r => r[0]) || [];
  const followers = db.exec('SELECT follower_id FROM follows WHERE following_id = ?', [u.id])[0]?.values.map(r => r[0]) || [];
  const badges = [];
  if (u.coins >= 100) badges.push('喵币富翁');
  if (db.exec('SELECT COUNT(*) as c FROM posts WHERE author_id = ?', [u.id])[0]?.values[0][0] >= 5) badges.push('发帖达人');
  res.json({ token, user: { ...u, password_hash: undefined, following, followers, badges } });
});

app.get('/api/user/me', auth, async (req, res) => {
  const db = await getDb();
  const user = db.exec('SELECT * FROM users WHERE id = ?', [req.user.id]);
  if (!user[0]) return res.status(404).json({ error: '用户不存在' });
  const cols = db.exec('PRAGMA table_info(users)')[0].values.map(c => c[1]);
  const u = Object.fromEntries(cols.map((c, i) => [c, user[0].values[0][i]]));
  const following = db.exec('SELECT following_id FROM follows WHERE follower_id = ?', [u.id])[0]?.values.map(r => r[0]) || [];
  const followers = db.exec('SELECT follower_id FROM follows WHERE following_id = ?', [u.id])[0]?.values.map(r => r[0]) || [];
  res.json({ ...u, password_hash: undefined, following, followers });
});

app.put('/api/user/profile', auth, async (req, res) => {
  const db = await getDb();
  const { name, avatar, school, major, bio } = req.body;
  if (name) db.run('UPDATE users SET name = ? WHERE id = ?', [name, req.user.id]);
  if (avatar) db.run('UPDATE users SET avatar = ? WHERE id = ?', [avatar, req.user.id]);
  if (school !== undefined) db.run('UPDATE users SET school = ? WHERE id = ?', [school, req.user.id]);
  if (major !== undefined) db.run('UPDATE users SET major = ? WHERE id = ?', [major, req.user.id]);
  if (bio !== undefined) db.run('UPDATE users SET bio = ? WHERE id = ?', [bio, req.user.id]);
  saveDb();
  res.json({ ok: true });
});

app.get('/api/user/:id', auth, async (req, res) => {
  const db = await getDb();
  const user = db.exec('SELECT * FROM users WHERE id = ?', [req.params.id]);
  if (!user[0]) return res.status(404).json({ error: '用户不存在' });
  const cols = db.exec('PRAGMA table_info(users)')[0].values.map(c => c[1]);
  const u = Object.fromEntries(cols.map((c, i) => [c, user[0].values[0][i]]));
  const following = db.exec('SELECT following_id FROM follows WHERE follower_id = ?', [u.id])[0]?.values.map(r => r[0]) || [];
  const followers = db.exec('SELECT follower_id FROM follows WHERE following_id = ?', [u.id])[0]?.values.map(r => r[0]) || [];
  const postCount = db.exec('SELECT COUNT(*) FROM posts WHERE author_id = ?', [u.id])[0]?.values[0][0] || 0;
  const likeCount = db.exec('SELECT COUNT(*) FROM post_likes pl JOIN posts p ON pl.post_id = p.id WHERE p.author_id = ?', [u.id])[0]?.values[0][0] || 0;
  res.json({ ...u, password_hash: undefined, following, followers, postCount, likeCount });
});

// --- Follow ---
app.post('/api/user/:id/follow', auth, async (req, res) => {
  const db = await getDb();
  if (req.params.id === req.user.id) return res.status(400).json({ error: '不能关注自己' });
  try {
    db.run('INSERT INTO follows (follower_id, following_id) VALUES (?,?)', [req.user.id, req.params.id]);
    saveDb();
    res.json({ ok: true });
  } catch { res.status(400).json({ error: '已经关注了' }); }
});

app.post('/api/user/:id/unfollow', auth, async (req, res) => {
  const db = await getDb();
  db.run('DELETE FROM follows WHERE follower_id = ? AND following_id = ?', [req.user.id, req.params.id]);
  saveDb();
  res.json({ ok: true });
});

// --- Posts ---
app.get('/api/posts', optionalAuth, async (req, res) => {
  const db = await getDb();
  const { board, circleId, tab, page = 1, limit = 20 } = req.query;
  let sql = 'SELECT * FROM posts WHERE 1=1';
  const params = [];
  if (board && board !== '全部') { sql += ' AND board = ?'; params.push(board); }
  if (circleId) { sql += ' AND circle_id = ?'; params.push(circleId); }
  if (tab === '精华') { sql += ' AND essence = 1'; }
  sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(Number(limit), (Number(page) - 1) * Number(limit));
  const rows = db.exec(sql, params);
  const cols = db.exec('PRAGMA table_info(posts)')[0].values.map(c => c[1]);
  const posts = (rows[0]?.values || []).map(v => {
    const p = Object.fromEntries(cols.map((c, i) => [c, v[i]]));
    p.tags = JSON.parse(p.tags || '[]');
    p.images = JSON.parse(p.images || '[]');
    p.anon = !!p.anon;
    p.essence = !!p.essence;
    p.likes = db.exec('SELECT COUNT(*) FROM post_likes WHERE post_id = ?', [p.id])[0]?.values[0][0] || 0;
    p.coins = db.exec('SELECT COALESCE(SUM(amount),0) FROM post_coins WHERE post_id = ?', [p.id])[0]?.values[0][0] || 0;
    p.collects = db.exec('SELECT COUNT(*) FROM post_collects WHERE post_id = ?', [p.id])[0]?.values[0][0] || 0;
    p.commentCount = db.exec('SELECT COUNT(*) FROM comments WHERE post_id = ?', [p.id])[0]?.values[0][0] || 0;
    if (req.user?.id) {
      p.liked = !!db.exec('SELECT 1 FROM post_likes WHERE post_id = ? AND user_id = ?', [p.id, req.user.id])[0];
      p.collected = !!db.exec('SELECT 1 FROM post_collects WHERE post_id = ? AND user_id = ?', [p.id, req.user.id])[0];
      p.coined = !!db.exec('SELECT 1 FROM post_coins WHERE post_id = ? AND user_id = ?', [p.id, req.user.id])[0];
    }
    return p;
  });
  res.json(posts);
});

app.get('/api/posts/hot', async (req, res) => {
  const db = await getDb();
  const { scope, limit = 20 } = req.query;
  const rows = db.exec('SELECT * FROM posts ORDER BY created_at DESC LIMIT 200');
  const cols = db.exec('PRAGMA table_info(posts)')[0].values.map(c => c[1]);
  let posts = (rows[0]?.values || []).map(v => {
    const p = Object.fromEntries(cols.map((c, i) => [c, v[i]]));
    p.tags = JSON.parse(p.tags || '[]');
    p.likes = db.exec('SELECT COUNT(*) FROM post_likes WHERE post_id = ?', [p.id])[0]?.values[0][0] || 0;
    p.coins = db.exec('SELECT COALESCE(SUM(amount),0) FROM post_coins WHERE post_id = ?', [p.id])[0]?.values[0][0] || 0;
    p.collects = db.exec('SELECT COUNT(*) FROM post_collects WHERE post_id = ?', [p.id])[0]?.values[0][0] || 0;
    p.commentCount = db.exec('SELECT COUNT(*) FROM comments WHERE post_id = ?', [p.id])[0]?.values[0][0] || 0;
    p.score = (p.likes || 0) * 3 + (p.collects || 0) * 5 + (p.commentCount || 0) * 2 + (p.coins || 0) * 8 + (p.views || 0) * 0.5;
    const age = (Date.now() - new Date(p.created_at).getTime()) / 3600000;
    if (scope === 'rising') p.score = p.score / Math.max(1, age);
    return p;
  });
  posts.sort((a, b) => b.score - a.score);
  res.json(posts.slice(0, Number(limit)));
});

app.get('/api/posts/:id', optionalAuth, async (req, res) => {
  const db = await getDb();
  db.run('UPDATE posts SET views = views + 1 WHERE id = ?', [req.params.id]);
  saveDb();
  const row = db.exec('SELECT * FROM posts WHERE id = ?', [req.params.id]);
  if (!row[0]) return res.status(404).json({ error: '帖子不存在' });
  const cols = db.exec('PRAGMA table_info(posts)')[0].values.map(c => c[1]);
  const p = Object.fromEntries(cols.map((c, i) => [c, row[0].values[0][i]]));
  p.tags = JSON.parse(p.tags || '[]');
  p.images = JSON.parse(p.images || '[]');
  p.anon = !!p.anon;
  p.essence = !!p.essence;
  p.likes = db.exec('SELECT COUNT(*) FROM post_likes WHERE post_id = ?', [p.id])[0]?.values[0][0] || 0;
  p.coins = db.exec('SELECT COALESCE(SUM(amount),0) FROM post_coins WHERE post_id = ?', [p.id])[0]?.values[0][0] || 0;
  p.collects = db.exec('SELECT COUNT(*) FROM post_collects WHERE post_id = ?', [p.id])[0]?.values[0][0] || 0;
  if (req.user?.id) {
    p.liked = !!db.exec('SELECT 1 FROM post_likes WHERE post_id = ? AND user_id = ?', [p.id, req.user.id])[0];
    p.collected = !!db.exec('SELECT 1 FROM post_collects WHERE post_id = ? AND user_id = ?', [p.id, req.user.id])[0];
    p.coined = !!db.exec('SELECT 1 FROM post_coins WHERE post_id = ? AND user_id = ?', [p.id, req.user.id])[0];
  }

  // comments
  const commentsRows = db.exec('SELECT * FROM comments WHERE post_id = ? ORDER BY created_at DESC', [p.id]);
  const cCols = db.exec('PRAGMA table_info(comments)')[0].values.map(c => c[1]);
  p.comments = (commentsRows[0]?.values || []).map(v => {
    const c = Object.fromEntries(cCols.map((col, i) => [col, v[i]]));
    c.likes = db.exec('SELECT COUNT(*) FROM comment_likes WHERE comment_id = ?', [c.id])[0]?.values[0][0] || 0;
    if (req.user?.id) c.likedByMe = !!db.exec('SELECT 1 FROM comment_likes WHERE comment_id = ? AND user_id = ?', [c.id, req.user.id])[0];
    c.likedBy = [];
    const repliesRows = db.exec('SELECT * FROM replies WHERE comment_id = ? ORDER BY created_at', [c.id]);
    const rCols = db.exec('PRAGMA table_info(replies)')[0].values.map(c => c[1]);
    c.replies = (repliesRows[0]?.values || []).map(v => Object.fromEntries(rCols.map((col, i) => [col, v[i]])));
    return c;
  });
  res.json(p);
});

app.post('/api/posts', auth, async (req, res) => {
  const db = await getDb();
  const { title, body, board, circleId, tags, images, anon } = req.body;
  const id = 'p_' + uuidv4().slice(0, 8);
  db.run('INSERT INTO posts (id, title, body, author_id, circle_id, board, tags, images, anon) VALUES (?,?,?,?,?,?,?,?,?)',
    [id, title, body || '', anon ? 'anonymous' : req.user.id, circleId || 'c_hall', board || '全部', JSON.stringify(tags || []), JSON.stringify(images || []), anon ? 1 : 0]);
  saveDb();
  res.json({ id, ok: true });
});

app.delete('/api/posts/:id', auth, async (req, res) => {
  const db = await getDb();
  db.run('DELETE FROM posts WHERE id = ? AND author_id = ?', [req.params.id, req.user.id]);
  saveDb();
  res.json({ ok: true });
});

// --- Post interactions ---
app.post('/api/posts/:id/like', auth, async (req, res) => {
  const db = await getDb();
  try { db.run('INSERT INTO post_likes (post_id, user_id) VALUES (?,?)', [req.params.id, req.user.id]); saveDb(); } catch {}
  res.json({ ok: true });
});
app.post('/api/posts/:id/unlike', auth, async (req, res) => {
  const db = await getDb();
  db.run('DELETE FROM post_likes WHERE post_id = ? AND user_id = ?', [req.params.id, req.user.id]);
  saveDb();
  res.json({ ok: true });
});
app.post('/api/posts/:id/collect', auth, async (req, res) => {
  const db = await getDb();
  try { db.run('INSERT INTO post_collects (post_id, user_id) VALUES (?,?)', [req.params.id, req.user.id]); saveDb(); } catch {}
  res.json({ ok: true });
});
app.post('/api/posts/:id/uncollect', auth, async (req, res) => {
  const db = await getDb();
  db.run('DELETE FROM post_collects WHERE post_id = ? AND user_id = ?', [req.params.id, req.user.id]);
  saveDb();
  res.json({ ok: true });
});
app.post('/api/posts/:id/coin', auth, async (req, res) => {
  const db = await getDb();
  const me = db.exec('SELECT coins FROM users WHERE id = ?', [req.user.id])[0]?.values[0][0] || 0;
  const postUser = db.exec('SELECT author_id FROM posts WHERE id = ?', [req.params.id])[0]?.values[0][0];
  if (me < 1) return res.status(400).json({ error: '喵币不够' });
  try {
    db.run('INSERT INTO post_coins (post_id, user_id, amount) VALUES (?,?,1)', [req.params.id, req.user.id]);
    db.run('UPDATE users SET coins = coins - 1 WHERE id = ?', [req.user.id]);
    if (postUser) db.run('UPDATE users SET coins = coins + 1 WHERE id = ?', [postUser]);
    saveDb();
    res.json({ ok: true });
  } catch { res.status(400).json({ error: '已经投过币了' }); }
});

// --- Comments ---
app.post('/api/posts/:id/comments', auth, async (req, res) => {
  const db = await getDb();
  const id = 'c_' + uuidv4().slice(0, 8);
  db.run('INSERT INTO comments (id, post_id, user_id, text) VALUES (?,?,?,?)', [id, req.params.id, req.user.id, req.body.text]);
  saveDb();
  res.json({ id, ok: true });
});

app.post('/api/comments/:id/like', auth, async (req, res) => {
  const db = await getDb();
  try { db.run('INSERT INTO comment_likes (comment_id, user_id) VALUES (?,?)', [req.params.id, req.user.id]); saveDb(); } catch {}
  res.json({ ok: true });
});
app.post('/api/comments/:id/unlike', auth, async (req, res) => {
  const db = await getDb();
  db.run('DELETE FROM comment_likes WHERE comment_id = ? AND user_id = ?', [req.params.id, req.user.id]);
  saveDb();
  res.json({ ok: true });
});

app.post('/api/comments/:id/reply', auth, async (req, res) => {
  const db = await getDb();
  const id = 'rp_' + uuidv4().slice(0, 8);
  db.run('INSERT INTO replies (id, comment_id, user_id, text) VALUES (?,?,?,?)', [id, req.params.id, req.user.id, req.body.text]);
  saveDb();
  res.json({ id, ok: true });
});

// --- Circles ---
app.get('/api/circles', async (req, res) => {
  const db = await getDb();
  const rows = db.exec('SELECT * FROM circles ORDER BY created_at DESC');
  const cols = db.exec('PRAGMA table_info(circles)')[0].values.map(c => c[1]);
  const circles = (rows[0]?.values || []).map(v => {
    const c = Object.fromEntries(cols.map((col, i) => [col, v[i]]));
    c.rules = JSON.parse(c.rules || '[]');
    c.members = db.exec('SELECT COUNT(*) FROM circle_members WHERE circle_id = ?', [c.id])[0]?.values[0][0] || 0;
    return c;
  });
  res.json(circles);
});

app.post('/api/circles', auth, async (req, res) => {
  const db = await getDb();
  const id = 'c_' + uuidv4().slice(0, 8);
  const { name, emoji, description } = req.body;
  db.run('INSERT INTO circles (id, name, emoji, description, owner_id, notice, rules) VALUES (?,?,?,?,?,?,?)',
    [id, name, emoji || '🌟', description || '', req.user.id, `${name}已建立`, JSON.stringify(['尊重同学，不挂人不网暴', '内容要和本吧主题相关', '广告/刷屏会被折叠'])]);
  db.run('INSERT INTO circle_members (circle_id, user_id) VALUES (?,?)', [id, req.user.id]);
  saveDb();
  res.json({ id, ok: true });
});

app.post('/api/circles/:id/join', auth, async (req, res) => {
  const db = await getDb();
  try { db.run('INSERT INTO circle_members (circle_id, user_id) VALUES (?,?)', [req.params.id, req.user.id]); saveDb(); } catch {}
  res.json({ ok: true });
});
app.post('/api/circles/:id/leave', auth, async (req, res) => {
  const db = await getDb();
  db.run('DELETE FROM circle_members WHERE circle_id = ? AND user_id = ?', [req.params.id, req.user.id]);
  saveDb();
  res.json({ ok: true });
});

// --- Messages ---
app.get('/api/messages/:userId', auth, async (req, res) => {
  const db = await getDb();
  const rows = db.exec('SELECT * FROM messages WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?) ORDER BY created_at',
    [req.user.id, req.params.userId, req.params.userId, req.user.id]);
  const cols = db.exec('PRAGMA table_info(messages)')[0].values.map(c => c[1]);
  const msgs = (rows[0]?.values || []).map(v => Object.fromEntries(cols.map((c, i) => [c, v[i]])));
  res.json(msgs);
});

app.post('/api/messages', auth, async (req, res) => {
  const db = await getDb();
  const id = 'm_' + uuidv4().slice(0, 8);
  const { toId, text, img } = req.body;
  db.run('INSERT INTO messages (id, from_id, to_id, text, img) VALUES (?,?,?,?,?)', [id, req.user.id, toId, text || '', img || '']);
  saveDb();
  res.json({ id, ok: true });
});

// --- Notifications ---
app.get('/api/notifications', auth, async (req, res) => {
  const db = await getDb();
  const rows = db.exec('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', [req.user.id]);
  const cols = db.exec('PRAGMA table_info(notifications)')[0].values.map(c => c[1]);
  const notifs = (rows[0]?.values || []).map(v => Object.fromEntries(cols.map((c, i) => [c, v[i]])));
  res.json(notifs);
});

app.post('/api/notifications', auth, async (req, res) => {
  const db = await getDb();
  const id = 'n_' + uuidv4().slice(0, 8);
  const { userId, title, icon, type, postId } = req.body;
  db.run('INSERT INTO notifications (id, user_id, title, icon, type, post_id) VALUES (?,?,?,?,?,?)', [id, userId, title, icon || '', type || '', postId || '']);
  saveDb();
  res.json({ id, ok: true });
});

app.post('/api/notifications/clear', auth, async (req, res) => {
  const db = await getDb();
  db.run('DELETE FROM notifications WHERE user_id = ?', [req.user.id]);
  saveDb();
  res.json({ ok: true });
});

// --- Reports ---
app.post('/api/reports', auth, async (req, res) => {
  const db = await getDb();
  const id = 'r_' + uuidv4().slice(0, 8);
  db.run('INSERT INTO reports (id, post_id, reason, reporter_id) VALUES (?,?,?,?)', [id, req.body.postId, req.body.reason, req.user.id]);
  saveDb();
  res.json({ id, ok: true });
});

app.get('/api/reports', auth, async (req, res) => {
  const db = await getDb();
  const rows = db.exec('SELECT * FROM reports ORDER BY created_at DESC');
  const cols = db.exec('PRAGMA table_info(reports)')[0].values.map(c => c[1]);
  const reports = (rows[0]?.values || []).map(v => Object.fromEntries(cols.map((c, i) => [c, v[i]])));
  res.json(reports);
});

app.post('/api/reports/:id/resolve', auth, async (req, res) => {
  const db = await getDb();
  db.run('DELETE FROM reports WHERE id = ?', [req.params.id]);
  saveDb();
  res.json({ ok: true });
});

// --- Sign in ---
app.post('/api/signin', auth, async (req, res) => {
  const db = await getDb();
  const today = new Date().toISOString().slice(0, 10);
  try {
    db.run('INSERT INTO daily_signins (user_id, date) VALUES (?,?)', [req.user.id, today]);
    db.run('UPDATE users SET coins = coins + 10 WHERE id = ?', [req.user.id]);
    saveDb();
    res.json({ ok: true });
  } catch { res.status(400).json({ error: '今天已签到' }); }
});

app.get('/api/signin/today', auth, async (req, res) => {
  const db = await getDb();
  const today = new Date().toISOString().slice(0, 10);
  const row = db.exec('SELECT 1 FROM daily_signins WHERE user_id = ? AND date = ?', [req.user.id, today]);
  res.json({ signed: !!row[0] });
});

// --- Stats ---
app.get('/api/stats', async (req, res) => {
  const db = await getDb();
  const posts = db.exec('SELECT COUNT(*) FROM posts')[0]?.values[0][0] || 0;
  const circles = db.exec('SELECT COUNT(*) FROM circles')[0]?.values[0][0] || 0;
  const users = db.exec('SELECT COUNT(*) FROM users')[0]?.values[0][0] || 0;
  const today = new Date().toISOString().slice(0, 10);
  const todayPosts = db.exec("SELECT COUNT(*) FROM posts WHERE date(created_at) = ?", [today])[0]?.values[0][0] || 0;
  res.json({ posts, circles, users, todayPosts });
});

// --- Admin seed ---
app.post('/api/admin/seed', auth, async (req, res) => {
  const db = await getDb();
  // Create default circles
  const defaultCircles = [
    { id: 'c_hall', name: '大厅', emoji: '🌐', desc: '全校公共表达区域' },
    { id: 'c_tree', name: '树洞', emoji: '🕳️', desc: '匿名倾诉、秘密分享' },
  ];
  for (const c of defaultCircles) {
    try {
      db.run('INSERT INTO circles (id, name, emoji, description, owner_id, notice, rules) VALUES (?,?,?,?,?,?,?)',
        [c.id, c.name, c.emoji, c.desc, 'u_system', `${c.name}欢迎你`, '[]']);
    } catch {}
  }
  saveDb();
  res.json({ ok: true });
});


// --- Sync State ---
app.post('/api/sync-state', auth, async (req, res) => {
  const db = await getDb();
  const { state: incoming } = req.body;
  if (!incoming) return res.json({ ok: true });
  
  // Merge global data (posts, users, circles)
  for (const key of ['posts', 'users', 'circles', 'reports']) {
    if (!incoming[key] || !Array.isArray(incoming[key])) continue;
    const existing = db.exec("SELECT value FROM sync_state WHERE key = ?", ['global_' + key]);
    let merged = [];
    if (existing[0]) {
      try {
        const existingArr = JSON.parse(existing[0].values[0][0]);
        const existingMap = new Map(existingArr.map(x => [x.id, x]));
        for (const item of incoming[key]) existingMap.set(item.id, item);
        merged = Array.from(existingMap.values());
      } catch { merged = incoming[key]; }
    } else {
      merged = incoming[key];
    }
    db.run("INSERT OR REPLACE INTO sync_state (key, value) VALUES (?, ?)", ['global_' + key, JSON.stringify(merged)]);
  }
  
  // Store user-specific data
  const userId = req.user.id;
  for (const key of ['messages', 'notifications', 'searchHistory', 'blocked', 'theme']) {
    if (incoming[key] !== undefined) {
      db.run("INSERT OR REPLACE INTO user_data (user_id, key, value) VALUES (?, ?, ?)",
        [userId, key, JSON.stringify(incoming[key])]);
    }
  }
  if (incoming.daily !== undefined) {
    db.run("INSERT OR REPLACE INTO user_data (user_id, key, value) VALUES (?, ?, ?)",
      [userId, 'daily', JSON.stringify(incoming.daily)]);
  }
  
  saveDb();
  res.json({ ok: true });
});

app.get('/api/sync-state', auth, async (req, res) => {
  const db = await getDb();
  const state = {};
  
  // Load global data
  for (const key of ['posts', 'users', 'circles', 'reports']) {
    const row = db.exec("SELECT value FROM sync_state WHERE key = ?", ['global_' + key]);
    if (row[0]) {
      try { state[key] = JSON.parse(row[0].values[0][0]); } catch { state[key] = []; }
    } else {
      state[key] = [];
    }
  }
  
  // Load user-specific data
  const userId = req.user.id;
  const userRows = db.exec("SELECT key, value FROM user_data WHERE user_id = ?", [userId]);
  if (userRows[0]) {
    for (const [key, value] of userRows[0].values) {
      try { state[key] = JSON.parse(value); } catch { state[key] = value; }
    }
  }
  
  // Add current user to state
  state.currentUserId = userId;
  
  // If empty, set defaults
  if (!state.posts || state.posts.length === 0) {
    state.posts = [];
  }
  if (!state.users || state.users.length === 0) {
    // Get current user from users table
    const me = db.exec("SELECT * FROM users WHERE id = ?", [userId]);
    if (me[0]) {
      const cols = db.exec("PRAGMA table_info(users)")[0].values.map(c => c[1]);
      const u = Object.fromEntries(cols.map((c, i) => [c, me[0].values[0][i]]));
      state.users = [u];
    }
  }
  if (!state.circles || state.circles.length === 0) {
    state.circles = [];
  }
  if (!state.reports) state.reports = [];
  if (!state.messages) state.messages = {};
  if (!state.notifications) state.notifications = [];
  if (!state.searchHistory) state.searchHistory = [];
  if (!state.blocked) state.blocked = [];
  
  res.json({ state });
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
