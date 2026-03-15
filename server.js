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

// 管理员路由
app.get('/admin/invite-codes', async (req, res) => {
  console.log('🛡️ 获取邀请码列表');
  res.json([]);
});

app.post('/admin/generate-invite', async (req, res) => {
  console.log('🛡️ 生成邀请码');
  const code = Math.random().toString(36).substring(2, 10).toUpperCase();
  res.json({ inviteCode: code });
});

// ======== 8. 静态文件服务 ========
const publicPath = path.join(__dirname, 'public');
console.log(`📁 静态文件路径: ${publicPath}`);

if (fs.existsSync(publicPath)) {
  app.use(express.static(publicPath));
  console.log('✅ 静态文件目录存在');
} else {
  console.warn('⚠️ 静态文件目录不存在，将自动创建');
  fs.mkdirSync(publicPath, { recursive: true });
}

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

// ======== 10. 错误处理 ========
app.use((err, req, res, next) => {
  console.error('💥 服务器错误:', err.message);
  if (!res.headersSent) {
    res.status(500).json({ error: '服务器内部错误' });
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
