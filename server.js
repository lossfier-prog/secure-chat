// ======== 1. 基础设置 ========
const http = require('http');
const express = require('express');
const WebSocket = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

// ======== 2. 立即输出日志（验证应用启动） ========
console.log('\n');
console.log('========================================');
console.log('🚀 EXPRESS APPLICATION STARTING...');
console.log('========================================');
console.log(`Time: ${new Date().toISOString()}`);
console.log(`Node: ${process.version}`);
console.log(`CWD: ${process.cwd()}`);
console.log(`PORT: ${process.env.PORT || 8080}`);
console.log('========================================\n');

// ======== 3. 创建 Express 应用 ========
const app = express();

// 中间件
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS 配置
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// ======== 4. 配置常量 ========
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-123';
const SALT_ROUNDS = 10;
/**
 * 生成唯一房间号 (8位字母+数字)
 */
function generateRoomId() {
  return Math.random().toString(36).substring(2, 10).toUpperCase();
}
// ======== 5. 数据库连接 ========
let pool = null;

function getPool() {
  if (pool) return pool;
  
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    console.error('❌ DATABASE_URL 环境变量缺失！');
    return null;
  }
  
  pool = new Pool({
    connectionString: dbUrl,
    ssl: { rejectUnauthorized: false },
    max: 10,
    connectionTimeoutMillis: 5000
  });
  
  pool.on('error', (err) => {
    console.error('❌ 数据库连接错误:', err.message);
  });
  
  return pool;
}

// ======== 6. 健康检查端点（最重要！） ========
app.get('/health', (req, res) => {
  console.log(`🏥 健康检查 [${new Date().toISOString()}]`);
  res.status(200).json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    port: PORT
  });
});
// ======================================================
// 中间件：验证 JWT 并解析用户
// ======================================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: '未授权' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: '无效令牌' });
    req.user = user;          // 挂载用户资料到 req 上
    next();
  });
};

// 中间件：仅管理员可访问
const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: '需要管理员权限' });
  }
  next();
};

// 中间件：仅房间所有者可访问
const roomOwnerOnly = async (req, res, next) => {
  const roomId = req.params.roomId;           // 从 URL 获取房间ID
  if (!roomId) return res.status(400).json({ error: '缺少房间ID' });

  const db = getPool();
  const room = await db.query('SELECT owner_id FROM rooms WHERE id = $1', [roomId]);
  
  if (room.rows.length === 0) {
    return res.status(404).json({ error: '房间不存在' });
  }
  
  // 当前用户是否是该房间所有者？
  if (room.rows[0].owner_id !== req.user.userId) {
    return res.status(403).json({ error: '只有房间所有者可操作' });
  }
  
  next();
};
// ======== 7. API 路由 ========

// 注册
app.post('/register', async (req, res) => {
  console.log('📝 收到注册请求');
  try {
    const { username, password, inviteCode } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: '用户名和密码必填' });
    }
    
    const db = getPool();
    if (!db) {
      return res.status(500).json({ error: '数据库连接失败' });
    }
    
    // 检查用户名是否存在
    const existing = await db.query('SELECT id FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: '用户名已存在' });
    }
    
    // 创建用户
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await db.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id',
      [username, passwordHash]
    );
    
    const token = jwt.sign(
      { userId: result.rows[0].id, username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    console.log(`✅ 用户注册成功: ${username}`);
    res.json({ token });
  } catch (err) {
    console.error('❌ 注册错误:', err.message);
    res.status(500).json({ error: '注册失败: ' + err.message });
  }
});

// 登录
app.post('/login', async (req, res) => {
  console.log('🔑 收到登录请求');
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: '用户名和密码必填' });
    }
    
    const db = getPool();
    if (!db) {
      return res.status(500).json({ error: '数据库连接失败' });
    }
    
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: '用户名或密码错误' });
    }
    
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(400).json({ error: '用户名或密码错误' });
    }
    
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    console.log(`✅ 用户登录成功: ${username}`);
    res.json({ token });
  } catch (err) {
    console.error('❌ 登录错误:', err.message);
    res.status(500).json({ error: '登录失败: ' + err.message });
  }
});

// 获取我的房间
app.get('/my-rooms', async (req, res) => {
  console.log('🏠 获取房间列表');
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: '未授权' });
    }
    
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const db = getPool();
    const result = await db.query(
      'SELECT id, room_id, created_at FROM rooms WHERE owner_id = $1',
      [decoded.userId]
    );
    
    res.json(result.rows.map(r => ({
      id: r.id,
      roomId: r.room_id.substring(0, 8) + '...',
      createdAt: r.created_at,
      pendingCount: 0
    })));
  } catch (err) {
    console.error('❌ 获取房间错误:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// 获取申请列表
app.get('/my-applications', async (req, res) => {
  console.log('📋 获取申请列表');
  res.json([]);
});

// ======================================================
// 管理员路由 — 仅管理员可访问！
// ======================================================

// 获取所有邀请码列表
app.get('/admin/invite-codes', authenticateToken, adminOnly, async (req, res) => {
  console.log('🛡️ 获取邀请码列表');
  try {
    const db = getPool();
    const result = await db.query('SELECT id, code, used, created_at FROM invite_codes');
    res.json(result.rows);
  } catch (err) {
    console.error('❌ 获取邀请码错误:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// 生成新邀请码（仅管理员）
app.post('/admin/generate-invite', authenticateToken, adminOnly, async (req, res) => {
  console.log('🛡️ 生成邀请码');
  try {
    const db = getPool();
    const code = Math.random().toString(36).substring(2, 10).toUpperCase();

    await db.query(
      'INSERT INTO invite_codes (code) VALUES ($1)',
      [code]
    );

    res.json({ inviteCode: code });
  } catch (err) {
    console.error('❌ 生成邀请码错误:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ======== 9. SPA 回退路由（必须在最后！） ========
app.get('*', (req, res) => {
  const indexPath = path.join(publicPath, 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send(`
      <!DOCTYPE html>
      <html>
      <head><title>安全聊天室</title></head>
      <body style="font-family: Arial; text-align: center; padding: 50px;">
        <h1>🔐 安全聊天室</h1>
        <p>服务器正在运行，但 index.html 尚未部署。</p>
        <p>请将前端文件放入 public/ 目录。</p>
        <hr>
        <p><a href="/health">健康检查</a></p>
      </body>
      </html>
    `);
  }
});
// ======================================================
// 房间管理 — 认证后可用
// ======================================================

// 创建新房间
app.post('/rooms', authenticateToken, async (req, res) => {
  console.log(`🏠 用户 ${req.user.username} 创建房间`);
  try {
    const db = getPool();
    const roomId = generateRoomId();   // 生成唯一房间号

    const result = await db.query(
      `INSERT INTO rooms (room_id, owner_id) 
       VALUES ($1, $2) 
       RETURNING id, room_id`,
      [roomId, req.user.userId]
    );

    // 自动将创建者加入房间成员
    await db.query(
      `INSERT INTO room_members (room_id, user_id) 
       VALUES ($1, $2)`,
      [result.rows[0].id, req.user.userId]
    );

    res.json({
      id: result.rows[0].id,
      roomId: result.rows[0].room_id,
      message: "房间创建成功！其他用户可用该房间号申请加入。"
    });

  } catch (err) {
    console.error('❌ 创建房间错误:', err.message);
    res.status(500).json({ error: '创建房间失败: ' + err.message });
  }
});
// ======== 10. 错误处理 ========
app.use((err, req, res, next) => {
  console.error('💥 服务器错误:', err.message);
  if (!res.headersSent) {
    res.status(500).json({ error: '服务器内部错误' });
  }
});
// 申请加入某个房间
app.post('/rooms/:roomId/join', authenticateToken, async (req, res) => {
  console.log(`📩 用户 ${req.user.username} 申请加入房间 ${req.params.roomId}`);
  try {
    const db = getPool();
    const { roomId } = req.params;

    // 1. 检查房间是否存在
    const room = await db.query('SELECT id FROM rooms WHERE room_id = $1', [roomId]);
    if (room.rows.length === 0) {
      return res.status(404).json({ error: '房间不存在！' });
    }
    const roomDbId = room.rows[0].id;

    // 2. 避免重复申请
    const existApp = await db.query(
      `SELECT id FROM applications 
       WHERE room_id = $1 AND applicant_id = $2 AND status = 'pending'`,
      [roomDbId, req.user.userId]
    );
    if (existApp.rows.length > 0) {
      return res.status(400).json({ error: '您已提交申请，请耐心等待审核' });
    }

    // 3. 创建申请记录
    await db.query(
      `INSERT INTO applications (room_id, applicant_id) 
       VALUES ($1, $2)`,
      [roomDbId, req.user.userId]
    );

    res.json({ message: '申请已提交！房间所有者会尽快审核。' });

  } catch (err) {
    console.error('❌ 申请加入错误:', err.message);
    res.status(500).json({ error: err.message });
  }
});
// 获取该房间的所有 pending 申请 （仅房间所有者）
app.get('/rooms/:roomId/applications', 
  authenticateToken, 
  roomOwnerOnly, 
  async (req, res) => 
{
  console.log(`📋 房间 ${req.params.roomId} 申请列表`);
  try {
    const db = getPool();
    const applications = await db.query(`
      SELECT 
        a.id, 
        a.status,
        u.id AS user_id,
        u.username
      FROM applications a
      JOIN users u ON a.applicant_id = u.id
      WHERE a.room_id = $1 AND a.status = 'pending'
      ORDER BY a.created_at DESC
    `, [req.params.roomId]);

    res.json(applications.rows);
  } catch (err) {
    console.error('❌ 获取申请列表错误:', err.message);
    res.status(500).json({ error: err.message });
  }
});
// 批准某条申请
app.post('/applications/:appId/approve', 
  authenticateToken, 
  async (req, res) => 
{
  console.log(`✅ 批准申请 ${req.params.appId}`);
  try {
    const db = getPool();
    const { appId } = req.params;

    // 1. 获取申请详情
    const app = await db.query(
      `SELECT room_id, applicant_id 
       FROM applications 
       WHERE id = $1 AND status = 'pending'`,
      [appId]
    );
    
    if (app.rows.length === 0) {
      return res.status(404).json({ error: '申请不存在或已处理' });
    }

    const { room_id, applicant_id } = app.rows[0];

    // 2. 验证操作者是房间所有者
    const room = await db.query('SELECT owner_id FROM rooms WHERE id = $1', [room_id]);
    if (room.rows[0].owner_id !== req.user.userId) {
      return res.status(403).json({ error: '无权操作该申请！' });
    }

    // 3. 更新申请状态 + 加入房间成员
    await db.query('BEGIN');
    await db.query(
      `UPDATE applications SET status = 'approved' WHERE id = $1`,
      [appId]
    );
    await db.query(
      `INSERT INTO room_members (room_id, user_id) 
       VALUES ($1, $2) 
       ON CONFLICT DO NOTHING`,   // 避免重复加入
      [room_id, applicant_id]
    );
    await db.query('COMMIT');

    res.json({ message: '申请已批准，用户已加入房间！' });

  } catch (err) {
    await db.query('ROLLBACK');
    console.error('❌ 批准申请错误:', err.message);
    res.status(500).json({ error: err.message });
  }
});
// 拒绝某条申请
app.post('/applications/:appId/reject', 
  authenticateToken, 
  async (req, res) => 
{
  console.log(`❌ 拒绝申请 ${req.params.appId}`);
  try {
    const db = getPool();
    const { appId } = req.params;

    // 检查申请是否存在且为 pending
    const app = await db.query(
      `SELECT room_id FROM applications 
       WHERE id = $1 AND status = 'pending'`,
      [appId]
    );
    
    if (app.rows.length === 0) {
      return res.status(404).json({ error: '申请不存在或已处理' });
    }

    // 验证操作者是房间所有者
    const room = await db.query('SELECT owner_id FROM rooms WHERE id = $1', [app.rows[0].room_id]);
    if (room.rows[0].owner_id !== req.user.userId) {
      return res.status(403).json({ error: '无权操作该申请！' });
    }

    await db.query(
      `UPDATE applications SET status = 'rejected' WHERE id = $1`,
      [appId]
    );

    res.json({ message: '申请已拒绝' });

  } catch (err) {
    console.error('❌ 拒绝申请错误:', err.message);
    res.status(500).json({ error: err.message });
  }
});
// ======== 11. 创建 HTTP 服务器 ========
const server = http.createServer(app);

// ======== 12. WebSocket 服务器 ========
const wss = new WebSocket.Server({ server });

wss.on('connection', (socket, req) => {
  console.log('🔌 新 WebSocket 连接');
  
  socket.on('message', (msg) => {
    console.log('📨 收到消息:', msg.toString().substring(0, 100));
  });
  
  socket.on('close', () => {
    console.log('👋 WebSocket 断开');
  });
});

// ======== 13. 数据库初始化 ========
async function initDatabase() {
  console.log('🔍 初始化数据库...');
  
  const db = getPool();
  if (!db) {
    console.error('❌ 无法连接数据库');
    return false;
  }
  
  try {
    // 测试连接
    await db.query('SELECT NOW()');
    console.log('✅ 数据库连接成功');
    
    // 创建表
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('   • users 表就绪');
    
    await db.query(`
      CREATE TABLE IF NOT EXISTS rooms (
        id SERIAL PRIMARY KEY,
        room_id TEXT UNIQUE NOT NULL,
        owner_id INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('   • rooms 表就绪');
    
    await db.query(`
      CREATE TABLE IF NOT EXISTS invite_codes (
        id SERIAL PRIMARY KEY,
        code TEXT UNIQUE NOT NULL,
        used BOOLEAN DEFAULT false,
        used_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('   • invite_codes 表就绪');
    
    await db.query(`
      CREATE TABLE IF NOT EXISTS applications (
        id SERIAL PRIMARY KEY,
        room_id INTEGER REFERENCES rooms(id),
        applicant_id INTEGER REFERENCES users(id),
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('   • applications 表就绪');

    // 房间成员表 —— 记录谁在哪个房间
  await db.query(`
  CREATE TABLE IF NOT EXISTS room_members (
    id SERIAL PRIMARY KEY,
    room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (room_id, user_id)   -- 同一用户不可重复加入同一个房间
  )
`);
console.log('   • room_members 表就绪');

// 申请表 —— 已存在，但确保有 status 字段
await db.query(`
  ALTER TABLE applications 
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending'
`);
    console.log('✅ 数据库初始化完成');
    return true;
  } catch (err) {
    console.error('❌ 数据库初始化失败:', err.message);
    return false;
  }
}

// ======== 14. 启动服务器（关键！） ========
async function startServer() {
  console.log('\n🚀 正在启动服务器...');
  
  // 初始化数据库（但不阻止启动）
  await initDatabase().catch(err => {
    console.warn('⚠️ 数据库初始化警告:', err.message);
  });
  
  // 关键！监听所有接口
  server.listen(PORT, '0.0.0.0', () => {
    console.log('\n========================================');
    console.log(`✅ 服务器成功启动！`);
    console.log(`   • 端口: ${PORT}`);
    console.log(`   • 地址: http://0.0.0.0:${PORT}`);
    console.log(`   • 健康检查: http://0.0.0.0:${PORT}/health`);
    console.log('========================================\n');
  });
  
  server.on('error', (err) => {
    console.error('💥 服务器启动失败:', err.message);
    process.exit(1);
  });
}

// ======== 15. 全局错误处理 ========
process.on('uncaughtException', (err) => {
  console.error('💥 未捕获异常:', err.message);
  console.error(err.stack);
});

process.on('unhandledRejection', (reason) => {
  console.error('💥 未处理的 Promise 拒绝:', reason);
});

// ======== 16. 启动！ ========
startServer();
