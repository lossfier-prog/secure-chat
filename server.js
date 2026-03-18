// ======== 1. 基础设置 ========
const http = require('http');
const express = require('express');
const WebSocket = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
// 👉 必须放在所有路由之前！
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-jwt-secret-key-here'; // 与你生成token时用的密钥一致

// 定义JWT验证中间件
const authenticateJWT = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: '未提供授权令牌' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: '无效的令牌格式' });

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // 将用户信息附加到req对象
    next(); // 继续执行后续路由
  } catch (err) {
    console.error('JWT验证失败:', err.message);
    res.status(401).json({ error: '无效或过期的令牌' });
  }
};
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
const SALT_ROUNDS = 10;

// 👇👇👇 新增这一行（非常重要！）👇👇👇
const publicPath = path.join(__dirname, 'public');   // 全局路径
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
  // 先查找房间的数据库ID
  const room = await db.query('SELECT owner_id FROM rooms WHERE room_id = $1', [roomId]);
  
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
//获取房间列表
app.get('/my-rooms', authenticateToken, async (req, res) => {
  console.log('🏠 获取房间列表');
  try {
    const db = getPool();
    // 按创建时间倒序，最新创建的房间排在最前面
    const result = await db.query(
      `SELECT id, room_id, created_at FROM rooms 
       WHERE owner_id = $1 
       ORDER BY created_at DESC`,
      [req.user.userId]
    );

    // 同时查询每个房间的待审核申请数量
    const roomsWithPending = await Promise.all(result.rows.map(async room => {
      const pendingRes = await db.query(
        `SELECT COUNT(*) FROM applications 
         WHERE room_id = $1 AND status = 'pending'`,
        [room.id]
      );
      return {
        id: room.id,
        roomId: room.room_id,
        createdAt: room.created_at,
        pendingCount: parseInt(pendingRes.rows[0].count)
      };
    }));

    res.json(roomsWithPending);
  } catch (err) {
    console.error('❌ 获取房间错误:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// 获取申请列表
app.get('/my-applications', authenticateToken, async (req, res) => {
  console.log('📋 获取申请列表');
  try {
    const db = getPool();
    const applications = await db.query(`
      SELECT 
        a.id, 
        a.status,
        r.room_id,
        u.username AS room_owner
      FROM applications a
      JOIN rooms r ON a.room_id = r.id
      JOIN users u ON r.owner_id = u.id
      WHERE a.applicant_id = $1
      ORDER BY a.created_at DESC
    `, [req.user.userId]);

    res.json(applications.rows);
  } catch (err) {
    console.error('❌ 获取申请列表错误:', err.message);
    res.status(500).json({ error: err.message });
  }
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
// ======== 8. 静态文件服务 ========
console.log(`📁 静态文件路径: ${publicPath}`); // ✅ 此处已使用全局变量

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
// ======================================================
// 房间管理 — 认证后可用
// ======================================================

// 创建新房间（仅管理员）
app.post('/rooms', authenticateToken, adminOnly, async (req, res) => {
  console.log(`🏠 管理员 ${req.user.username} 创建房间`);
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
      message: "房间创建成功！请将房间号分享给需要加入的用户。"
    });

  } catch (err) {
    console.error('❌ 创建房间错误:', err.message);
    res.status(500).json({ error: '创建房间失败: ' + err.message });
  }
});

// 删除房间
app.delete('/rooms/:roomId', authenticateToken, roomOwnerOnly, async (req, res) => {
  console.log(`🗑️ 用户 ${req.user.username} 删除房间 ${req.params.roomId}`);
  try {
    const db = getPool();
    const { roomId } = req.params;

    // 先查找房间的数据库ID
    const roomResult = await db.query('SELECT id FROM rooms WHERE room_id = $1', [roomId]);
    if (roomResult.rows.length === 0) {
      return res.status(404).json({ error: '房间不存在' });
    }
    const roomDbId = roomResult.rows[0].id;

    // 开始事务
    await db.query('BEGIN');

    try {
      // 删除房间相关的所有数据
      // 1. 删除消息
      await db.query('DELETE FROM messages WHERE room_id = $1', [roomDbId]);
      // 2. 删除房间成员
      await db.query('DELETE FROM room_members WHERE room_id = $1', [roomDbId]);
      // 3. 删除申请
      await db.query('DELETE FROM applications WHERE room_id = $1', [roomDbId]);
      // 4. 删除房间
      const deleteResult = await db.query('DELETE FROM rooms WHERE id = $1', [roomDbId]);

      await db.query('COMMIT');

      if (deleteResult.rowCount > 0) {
        res.json({ message: '房间删除成功' });
      } else {
        res.status(404).json({ error: '房间不存在' });
      }
    } catch (err) {
      await db.query('ROLLBACK');
      throw err;
    }

  } catch (err) {
    console.error('❌ 删除房间错误:', err.message);
    res.status(500).json({ error: '删除房间失败: ' + err.message });
  }
});

// 加入房间（直接通过房间号）
app.post('/rooms/:roomId/join', authenticateToken, async (req, res) => {
  console.log(`📩 用户 ${req.user.username} 加入房间 ${req.params.roomId}`);
  try {
    const db = getPool();
    const { roomId } = req.params;

    // 1. 检查房间是否存在
    const room = await db.query('SELECT id FROM rooms WHERE room_id = $1', [roomId]);
    if (room.rows.length === 0) {
      return res.status(404).json({ error: '房间不存在！' });
    }
    const roomDbId = room.rows[0].id;

    // 2. 检查用户是否已经是房间成员
    const existingMember = await db.query(
      'SELECT * FROM room_members WHERE room_id = $1 AND user_id = $2',
      [roomDbId, req.user.userId]
    );
    if (existingMember.rows.length > 0) {
      return res.status(400).json({ error: '您已经是该房间的成员' });
    }

    // 3. 将用户加入房间
    await db.query(
      `INSERT INTO room_members (room_id, user_id) 
       VALUES ($1, $2)`,
      [roomDbId, req.user.userId]
    );

    res.json({ message: '加入房间成功！' });

  } catch (err) {
    console.error('❌ 加入房间错误:', err.message);
    res.status(500).json({ error: '加入房间失败: ' + err.message });
  }
});
// ======== 10. 错误处理 ========
app.use((err, req, res, next) => {
  console.error('💥 服务器错误:', err.message);
  if (!res.headersSent) {
    res.status(500).json({ error: '服务器内部错误' });
  }
});


// 获取房间历史消息
app.get('/rooms/:roomId/messages', authenticateToken, async (req, res) => {
  console.log(`📜 获取房间 ${req.params.roomId} 历史消息`);
  try {
    const db = getPool();
    const { roomId } = req.params;
    const { limit = 50, offset = 0 } = req.query;

    // 查找房间ID
    const roomResult = await db.query('SELECT id FROM rooms WHERE room_id = $1', [roomId]);
    if (roomResult.rows.length === 0) {
      return res.status(404).json({ error: '房间不存在' });
    }

    const roomDbId = roomResult.rows[0].id;

    // 验证用户是否是房间成员
    const memberResult = await db.query('SELECT * FROM room_members WHERE room_id = $1 AND user_id = $2', [roomDbId, req.user.userId]);
    if (memberResult.rows.length === 0) {
      return res.status(403).json({ error: '您不是该房间的成员' });
    }

    // 获取消息，按时间倒序，最新的消息在前面
    const messages = await db.query(`
      SELECT 
        m.id, 
        m.content, 
        m.created_at, 
        u.username
      FROM messages m
      JOIN users u ON m.user_id = u.id
      WHERE m.room_id = $1
      ORDER BY m.created_at DESC
      LIMIT $2 OFFSET $3
    `, [roomDbId, parseInt(limit), parseInt(offset)]);

    // 反转消息顺序，使最早的消息在前面
    const reversedMessages = messages.rows.reverse();

    res.json(reversedMessages);

  } catch (err) {
    console.error('❌ 获取消息错误:', err.message);
    res.status(500).json({ error: err.message });
  }
});
// ======== 11. 创建 HTTP 服务器 ========
const server = http.createServer(app);

// ======== 12. WebSocket 服务器 ========
const wss = new WebSocket.Server({ server });

// 用户连接与房间的映射
const userConnections = new Map();
const roomOwners = new Map(); // 房间id -> 房主的WebSocket连接

wss.on('connection', (socket, req) => {
  let userId = null;
  let username = null;

  console.log('🔌 新WebSocket连接');

  // 验证token（从query参数或cookie中获取）
  const token = req.url.split('token=')[1];
  if (!token) {
    socket.close(1008, '未授权');
    return;
  }

  try {
    const decoded = jwt.verify(token.split('&')[0], JWT_SECRET);
    userId = decoded.userId;
    username = decoded.username;

    // 保存用户连接信息
    userConnections.set(userId, socket);
    socket.userId = userId;
    socket.username = username;

    socket.send(JSON.stringify({
      type: 'system',
      text: `👋 欢迎 ${username}，你已连接到聊天服务器`
    }));
  } catch (err) {
    console.error('WebSocket验证失败:', err);
    socket.close(1008, '无效token');
    return;
  }

  socket.on('message', async (msg) => {
    try {
      const data = JSON.parse(msg);

      console.log(`📨 收到消息 (${username}):`, data.type);

      // 处理其他消息类型...
      if (data.type === 'chatMessage') {
        // 存储消息到数据库
        const db = getPool();
        if (db) {
          // 查找房间ID
          db.query('SELECT id FROM rooms WHERE room_id = $1', [data.roomId])
            .then(roomResult => {
              if (roomResult.rows.length > 0) {
                const roomDbId = roomResult.rows[0].id;
                // 验证用户是否是房间成员
                return db.query('SELECT * FROM room_members WHERE room_id = $1 AND user_id = $2', [roomDbId, userId]);
              }
              throw new Error('房间不存在');
            })
            .then(memberResult => {
              if (memberResult.rows.length > 0) {
                const roomDbId = memberResult.rows[0].room_id;
                // 存储消息
                return db.query(
                  'INSERT INTO messages (room_id, user_id, content) VALUES ($1, $2, $3) RETURNING id, created_at',
                  [roomDbId, userId, data.message]
                );
              }
              throw new Error('您不是该房间的成员');
            })
            .then(async () => {
              // 转发聊天消息
              await broadcastToRoom(data.roomId, {
                type: 'chatMessage',
                from: username,
                message: data.message,
                timestamp: new Date().toISOString()
              });
            })
            .catch(err => {
              console.error('存储消息错误:', err.message);
              socket.send(JSON.stringify({
                type: 'error',
                message: err.message
              }));
            });
        }
      }
      // 其他消息类型处理...
    } catch (err) {
      console.error('处理WebSocket消息错误:', err);
    }
  });

  socket.on('close', () => {
    if (userId) {
      console.log(`👋 用户断开连接: ${username}`);
      userConnections.delete(userId);

      // 如果是房主，从roomOwners中移除
      for (let [roomId, ownerId] of roomOwners.entries()) {
        if (ownerId === userId) {
          roomOwners.delete(roomId);
        }
      }
    }
  });
});

// 广播消息到房间
async function broadcastToRoom(roomId, message) {
  if (!roomId) return;

  try {
    const db = getPool();
    if (!db) return;

    // 查找房间ID
    const roomResult = await db.query('SELECT id FROM rooms WHERE room_id = $1', [roomId]);
    if (roomResult.rows.length === 0) return;

    const roomDbId = roomResult.rows[0].id;

    // 获取房间所有成员
    const membersResult = await db.query('SELECT user_id FROM room_members WHERE room_id = $1', [roomDbId]);
    const memberIds = membersResult.rows.map(row => row.user_id);

    // 只向房间成员发送消息
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN && client.userId && memberIds.includes(client.userId)) {
        client.send(JSON.stringify(message));
      }
    });
  } catch (err) {
    console.error('广播消息错误:', err.message);
  }
}

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
        password_hash TEXT,
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

// 聊天消息表
await db.query(`
  CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);
console.log('   • messages 表就绪');

// 申请表 —— 已存在，但确保有 status 字段
await db.query(`
  ALTER TABLE applications 
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending'
`);

// 为rooms表添加password_hash字段
await db.query(`
  ALTER TABLE rooms 
  ADD COLUMN IF NOT EXISTS password_hash TEXT
`);
    console.log('✅ 数据库初始化完成');
    return true;
  } catch (err) {
    console.error('❌ 数据库初始化失败:', err.message);
    return false;
  }
}

// 定期清理3天前的消息
async function cleanOldMessages() {
  try {
    const db = getPool();
    if (!db) return;

    // 删除3天前的消息
    const result = await db.query(
      'DELETE FROM messages WHERE created_at < NOW() - INTERVAL \'3 days\''
    );

    console.log(`🧹 清理了 ${result.rowCount} 条3天前的消息`);
  } catch (err) {
    console.error('清理旧消息错误:', err.message);
  }
}

// ======== 14. 启动服务器（关键！） ========
async function startServer() {
  console.log('\n🚀 正在启动服务器...');
  
  // 初始化数据库（但不阻止启动）
  await initDatabase().catch(err => {
    console.warn('⚠️ 数据库初始化警告:', err.message);
  });
  
  // 启动定期清理任务（每24小时执行一次）
  setInterval(cleanOldMessages, 24 * 60 * 60 * 1000);
  // 启动时执行一次清理
  cleanOldMessages();
  
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
