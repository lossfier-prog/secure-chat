// ======== 1. 日志系统（必须是第一行！） ========
require('./logger');
const logger = require('./logger');

// ======== 2. 导入模块 ========
const http = require('http');
const express = require('express');
const WebSocket = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

// ======== 3. 创建应用 ========
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ======== 4. 全局未捕获错误处理（必须在任何路由之前！） ========
process.on('uncaughtException', (err) => {
  logger.error('💥 未捕获异常:', err.message, err.stack);
  try { process.stdout.write('\n'); } catch(e) {}
  setTimeout(() => process.exit(1), 200);
});

process.on('unhandledRejection', (reason) => {
  logger.error('💥 未处理的 Promise 拒绝:', reason);
});

// ======== 5. 配置常量 ========
const JWT_SECRET = process.env.JWT_SECRET || 'YOUR_SECURE_SECRET_KEY_123!';
const SALT_ROUNDS = 10;
const PORT = process.env.PORT || 8080;

let pool = null;

// ======== 6. 健康检查端点 ========
app.get('/health', (req, res) => {
  logger.info('🏥 健康检查:', req.ip);
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ======== 7. SPA 回退路由（必须放在最后！） ========
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ======== 8. 错误处理中间件（必须是最后一个！） ========
app.use((err, req, res, next) => {
  try {
    logger.error('💥 服务器错误 [', req.method, req.url, ']:', err.message);
    
    if (!res.headersSent) {
      res.status(err.statusCode || 500).json({
        error: 'INTERNAL_SERVER_ERROR',
        message: process.env.NODE_ENV === 'production' 
          ? '服务器内部错误' 
          : err.message
      });
    }
  } catch (handlerErr) {
    logger.error('❌ 错误处理自身崩溃:', handlerErr.message);
    if (!res.headersSent) {
      res.statusCode = 500;
      res.end('Server Error');
    }
  }
});

// ======== 9. 数据库连接（安全的） ========
function createPool() {
  if (pool) return pool;
  
  const connectionString = process.env.DATABASE_URL;
  
  if (!connectionString) {
    logger.error('❌ DATABASE_URL 缺失！无法启动');
    throw new Error('DATABASE_URL environment variable required');
  }

  pool = new Pool({
    connectionString,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 5000,
    max: 10
  });

  pool.on('error', (err) => {
    logger.error('❌ 数据库池错误:', err.message);
  });

  return pool;
}

async function initDB() {
  try {
    logger.info('🔍 开始数据库初始化...');
    const p = createPool();
    
    await p.query('SELECT NOW()');
    logger.info('✅ 数据库连接成功');
    
    // 创建表结构
    const tables = [
      { name: 'users', sql: `CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT DEFAULT 'user', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)` },
      { name: 'rooms', sql: `CREATE TABLE IF NOT EXISTS rooms (id SERIAL PRIMARY KEY, room_id TEXT UNIQUE NOT NULL, owner_id INTEGER REFERENCES users(id), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)` },
      { name: 'invite_codes', sql: `CREATE TABLE IF NOT EXISTS invite_codes (id SERIAL PRIMARY KEY, code TEXT UNIQUE NOT NULL, used BOOLEAN DEFAULT false, used_by INTEGER REFERENCES users(id), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)` },
      { name: 'applications', sql: `CREATE TABLE IF NOT EXISTS applications (id SERIAL PRIMARY KEY, room_id INTEGER REFERENCES rooms(id), applicant_id INTEGER REFERENCES users(id), status TEXT DEFAULT 'pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)` }
    ];

    for (const table of tables) {
      await p.query(table.sql);
      logger.info(`   • ${table.name} 表创建完成`);
    }
    
    logger.info('🎉 数据库初始化完成');
    return true;
  } catch (err) {
    logger.error('❌ 数据库初始化失败:', err.message);
    
    if (err.code === 'ECONNREFUSED') {
      logger.error(`
===========================================
⚠️ 数据库连接失败！请检查：
1. PostgreSQL 服务是否已连接到本应用？
2. DATABASE_URL 环境变量是否存在？
3. 数据库实例是否正在运行？
===========================================
      `);
    }
    
    throw err;
  }
}

// ==================== API 路由 ====================
const authenticateJWT = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ error: 'Invalid token' });
      req.user = user;
      next();
    });
  } catch (err) {
    logger.error('认证错误:', err.message);
    res.status(500).json({ error: 'Auth error' });
  }
};

const adminOnly = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
};

// 示例注册路由
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id',
      [username, passwordHash]
    );
    
    const token = jwt.sign({ userId: result.rows[0].id, username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
    logger.info(`👤 新用户注册: ${username}`);
  } catch (err) {
    logger.error('注册错误:', err.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// 示例登录路由
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    
    if (!match) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
    logger.info(`🔑 用户登录: ${username}`);
  } catch (err) {
    logger.error('登录错误:', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ==================== WebSocket ====================
wss.on('connection', (socket, request) => {
  const url = new URL(request.url, `http://${request.headers.host}`);
  const token = url.searchParams.get('token');

  if (!token) {
    socket.close(1008, 'No token');
    return;
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      socket.close(1008, 'Invalid token');
      return;
    }
    
    socket.userId = user.userId;
    socket.username = user.username;
    logger.info(`👤 WebSocket 连接: ${user.username}`);
  });

  socket.on('message', (rawMsg) => {
    try {
      const msg = JSON.parse(rawMsg.toString());
      if (msg.type === 'msg') {
        // 消息处理逻辑
      }
    } catch (e) {
      logger.error('消息解析错误:', e.message);
    }
  });

  socket.on('close', () => {
    logger.info(`👋 连接断开: ${socket.username}`);
  });
});

// ==================== 启动服务器 ====================
initDB()
  .then(() => {
    server.listen(PORT, '0.0.0.0', () => {
      logger.info(`\n\n🚀 服务器启动成功: http://0.0.0.0:${PORT}`);
      logger.info(`🌐 可访问: https://${process.env.RAILWAY_STATIC_URL}`);
    });
  })
  .catch((err) => {
    logger.error('💥 服务器启动失败:', err.message);
    process.exit(1);
  });
