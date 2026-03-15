require('dotenv').config();
const http = require('http');
const express = require('express');
const WebSocket = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ==================== 安全配置 ====================
const JWT_SECRET = process.env.JWT_SECRET || 'YOUR_SECURE_SECRET_KEY_123!';
const SALT_ROUNDS = 10;
const SALT = process.env.SALT || 'MySuperSecretSalt_9876';

// ==================== 数据库连接 ====================
let pool;

function createPool() {
  if (pool) return pool;
  
  const connectionString = process.env.DATABASE_URL;
  
  if (!connectionString) {
    console.error('❌ 未找到 DATABASE_URL 环境变量！');
    console.error('请确保：');
    console.error('1. 已在 Railway 添加 PostgreSQL 服务');
    console.error('2. 数据库服务与应用服务已连接');
    throw new Error('缺少 DATABASE_URL 环境变量');
  }

  console.log('🔌 正在初始化数据库连接池...');
  pool = new Pool({
    connectionString: connectionString,
    ssl: {
      rejectUnauthorized: false // Railway 必需
    },
    connectionTimeoutMillis: 5000,
    max: 20
  });

  pool.on('error', (err) => {
    console.error('❌ 数据库连接池意外错误:', err);
  });

  return pool;
}

// 增强的数据库连接重试逻辑
async function connectWithRetry(maxRetries = 5, delay = 3000) {
  let attempts = 0;
  
  while (attempts < maxRetries) {
    try {
      const p = createPool();
      await p.query('SELECT NOW()');
      console.log('✅ 数据库连接成功！');
      return p;
    } catch (err) {
      attempts++;
      console.error(`❌ 数据库连接失败 (尝试 ${attempts}/${maxRetries}):`, err.message);
      
      if (attempts >= maxRetries) {
        console.error('🛑 达到最大重试次数，启动终止');
        throw err;
      }
      
      console.log(`⏳ ${delay/1000}秒后重试...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// ==================== 初始化数据库与建表 ====================
async function initDB() {
  try {
    // 1. 等待连接
    await connectWithRetry(10, 5000);
    
    console.log('🔍 开始检查并创建数据库表...');
    
    // 创建用户表
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
      )
    `);
    console.log('✅ Users 表就绪');

    // 创建房间表
    await pool.query(`
      CREATE TABLE IF NOT EXISTS rooms (
        id SERIAL PRIMARY KEY,
        room_id TEXT UNIQUE NOT NULL,
        owner_id INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Rooms 表就绪');

    // 创建邀请码表
    await pool.query(`
      CREATE TABLE IF NOT EXISTS invite_codes (
        id SERIAL PRIMARY KEY,
        code TEXT UNIQUE NOT NULL,
        used BOOLEAN DEFAULT false,
        used_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        used_at TIMESTAMP
      )
    `);
    console.log('✅ InviteCodes 表就绪');

    // 创建申请表
    await pool.query(`
      CREATE TABLE IF NOT EXISTS applications (
        id SERIAL PRIMARY KEY,
        room_id INTEGER REFERENCES rooms(id),
        applicant_id INTEGER REFERENCES users(id),
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        responded_at TIMESTAMP
      )
    `);
    console.log('✅ Applications 表就绪');
    
    console.log('🎉 所有数据库表初始化完成');
    
    // 检查并创建管理员
    const adminCheck = await pool.query(
      'SELECT id FROM users WHERE username = $1', 
      ['admin']
    );
    
    if (adminCheck.rows.length === 0) {
      const adminPassword = process.env.ADMIN_PASSWORD || 'SecureAdmin123!';
      const passwordHash = await bcrypt.hash(adminPassword, SALT_ROUNDS);
      
      await pool.query(
        `INSERT INTO users (username, password_hash, role) 
         VALUES ($1, $2, 'admin')`,
        ['admin', passwordHash]
      );
      
      console.log(`🛡️ 管理员账户已创建！
  用户名: admin
  密码: ${adminPassword}
  请立即登录并修改密码！`);
    }
  } catch (err) {
    console.error('❌ 数据库初始化严重错误:', err);
    if (err.code === 'ECONNREFUSED') {
      console.error('提示: 检查 Railway 数据库是否已连接');
    }
    throw err;
  }
}

// ==================== 静态文件服务 (SPA) ====================
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== 路由 ====================

// 健康检查
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', port: process.env.PORT });
});

// 中间件
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: '未提供认证令牌' });
  const token = authHeader.split(' ')[1];
  
  jwt.verify(token, JWT_SECRET, async (err, user) => {
    if (err) return res.status(403).json({ error: '无效的令牌' });
    
    const result = await pool.query(
      'SELECT id, username, role FROM users WHERE id = $1', 
      [user.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(403).json({ error: '用户不存在' });
    }
    req.user = result.rows[0];
    next();
  });
};

const adminOnly = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: '需要管理员权限' });
  }
  next();
};

// 生成邀请码
app.post('/admin/generate-invite', authenticateJWT, adminOnly, async (req, res) => {
  try {
    const code = Math.random().toString(36).substring(2, 10).toUpperCase();
    await pool.query('INSERT INTO invite_codes (code) VALUES ($1)', [code]);
    console.log(`🛡️ 管理员 ${req.user.username} 生成了邀请码: ${code}`);
    res.json({ inviteCode: code });
  } catch (err) {
    console.error('生成邀请码错误:', err);
    res.status(500).json({ error: '生成失败' });
  }
});

// 查看邀请码
app.get('/admin/invite-codes', authenticateJWT, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, code, used, created_at, used_at,
             (SELECT username FROM users WHERE id = used_by) as used_by
      FROM invite_codes
      ORDER BY created_at DESC
      LIMIT 50
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: '查询失败' });
  }
});

// 注册
app.post('/register', async (req, res) => {
  const { username, password, inviteCode } = req.body;
  if (!username || !password || !inviteCode) {
    return res.status(400).json({ error: '缺少必要参数' });
  }

  try {
    const inviteResult = await pool.query(
      'SELECT * FROM invite_codes WHERE code = $1 AND used = false', 
      [inviteCode]
    );
    
    if (inviteResult.rows.length === 0) {
      return res.status(400).json({ error: '邀请码无效或已使用' });
    }

    const userResult = await pool.query(
      'SELECT id FROM users WHERE username = $1', 
      [username]
    );
    
    if (userResult.rows.length > 0) {
      return res.status(400).json({ error: '用户名已被占用' });
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const userResult2 = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id',
      [username, passwordHash]
    );
    
    const userId = userResult2.rows[0].id;
    
    await pool.query(
      `UPDATE invite_codes SET used = true, used_by = $1, used_at = CURRENT_TIMESTAMP WHERE id = $2`,
      [userId, inviteResult.rows[0].id]
    );

    const token = jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
  } catch (err) {
    console.error('注册错误:', err);
    res.status(500).json({ error: '注册失败' });
  }
});

// 登录
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '缺少参数' });

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1', 
      [username]
    );
    
    if (result.rows.length === 0) {
      return res.status(400).json({ error: '用户名或密码错误' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ error: '用户名或密码错误' });
    }

    await pool.query(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );

    const token = jwt.sign({ userId: user.id, username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
  } catch (err) {
    console.error('登录错误:', err);
    res.status(500).json({ error: '登录失败' });
  }
});

// 我的房间
app.get('/my-rooms', authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT r.id, r.room_id, r.created_at,
             (SELECT COUNT(*) FROM applications a WHERE a.room_id = r.id AND a.status = 'pending') AS pending_count
      FROM rooms r
      WHERE r.owner_id = $1
      ORDER BY r.created_at DESC
    `, [req.user.id]);
    
    const rooms = result.rows.map(room => ({
      id: room.id,
      roomId: room.room_id.substring(0, 8) + '…',
      createdAt: room.created_at,
      pendingCount: room.pending_count || 0
    }));

    res.json(rooms);
  } catch (err) {
    res.status(500).json({ error: '数据库错误' });
  }
});

// 审批通过
app.post('/applications/:appId/approve', authenticateJWT, async (req, res) => {
  try {
    const appId = req.params.appId;
    const result = await pool.query(`
      SELECT a.*, r.owner_id FROM applications a JOIN rooms r ON a.room_id = r.id WHERE a.id = $1
    `, [appId]);
    
    const app = result.rows[0];
    if (!app || app.owner_id !== req.user.id) return res.status(403).json({ error: '无权限' });

    await pool.query(`UPDATE applications SET status = 'approved', responded_at = CURRENT_TIMESTAMP WHERE id = $1`, [appId]);

    wss.clients.forEach(client => {
      if (client.userId === app.applicant_id && client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ type: 'application_approved', roomDbId: app.room_id }));
      }
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: '操作失败' });
  }
});

// 审批拒绝
app.post('/applications/:appId/reject', authenticateJWT, async (req, res) => {
  try {
    const appId = req.params.appId;
    const result = await pool.query(`
      SELECT a.*, r.owner_id FROM applications a JOIN rooms r ON a.room_id = r.id WHERE a.id = $1
    `, [appId]);
    
    const app = result.rows[0];
    if (!app || app.owner_id !== req.user.id) return res.status(403).json({ error: '无权限' });

    await pool.query(`UPDATE applications SET status = 'rejected', responded_at = CURRENT_TIMESTAMP WHERE id = $1`, [appId]);

    wss.clients.forEach(client => {
      if (client.userId === app.applicant_id && client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ type: 'application_rejected' }));
      }
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: '操作失败' });
  }
});

// 我的申请
app.get('/my-applications', authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT a.id, a.room_id, a.status, a.created_at, u.username AS applicant_name
      FROM applications a
      JOIN users u ON a.applicant_id = u.id
      WHERE a.room_id IN (SELECT id FROM rooms WHERE owner_id = $1) AND a.status = 'pending'
    `, [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: '查询失败' });
  }
});

// ==================== WebSocket ====================
const wsRooms = new Map();

wss.on('connection', (socket, request) => {
  const url = new URL(request.url, `http://${request.headers.host}`);
  const token = url.searchParams.get('token');

  if (!token) {
    socket.close(1008, '❌ 未提供 Token');
    return;
  }

  jwt.verify(token, JWT_SECRET, async (err, user) => {
    if (err) {
      socket.close(1008, '❌ 无效 Token');
      return;
    }
    
    const result = await pool.query('SELECT id, username FROM users WHERE id = $1', [user.userId]);
    if (result.rows.length === 0) {
      socket.close(1008, '❌ 用户不存在');
      return;
    }
    
    const userInfo = result.rows[0];
    socket.userId = userInfo.id;
    socket.username = userInfo.username;
    console.log(`👤 ${userInfo.username} 连接成功`);
  });

  socket.on('message', async (rawMsg) => {
    try {
      const msg = JSON.parse(rawMsg.toString());

      // 房主直接进入
      if (msg.type === 'join-as-owner') {
        const { roomIdHash } = msg;
        const fullHash = roomIdHash.replace('…', '');
        const result = await pool.query('SELECT * FROM rooms WHERE room_id LIKE $1', [fullHash + '%']);
        const room = result.rows[0];
        
        if (!room) return socket.send(JSON.stringify({ type: 'error', text: '房间不存在' }));
        
        const ownerResult = await pool.query('SELECT owner_id FROM rooms WHERE id = $1', [room.id]);
        if (ownerResult.rows[0].owner_id !== socket.userId) {
          return socket.send(JSON.stringify({ type: 'error', text: '无权限进入' }));
        }

        socket.roomDbId = room.id;
        socket.isOwner = true;
        joinWsRoom(socket, room.id);
        socket.send(JSON.stringify({ type: 'system', text: `✅ 已进入你的房间【${roomIdHash}】` }));
        return;
      }

      // 密码加入
      if (msg.type === 'join') {
        const { password } = msg;
        const roomIdHash = require('crypto').createHash('sha256').update(password + SALT).digest('hex').slice(0, 16);
        const roomResult = await pool.query('SELECT * FROM rooms WHERE room_id = $1', [roomIdHash]);
        const room = roomResult.rows[0];

        if (!room) {
          // 创建房间
          const result = await pool.query('INSERT INTO rooms (room_id, owner_id) VALUES ($1, $2) RETURNING id', [roomIdHash, socket.userId]);
          const newRoomId = result.rows[0].id;
          socket.roomDbId = newRoomId;
          socket.isOwner = true;
          wsRooms.set(newRoomId, new Set());
          wsRooms.get(newRoomId).add(socket);
          socket.send(JSON.stringify({ type: 'system', text: `✅ 你已成为房间【${roomIdHash.slice(0,8)}】的房主！` }));
        } else {
          const roomDbId = room.id;
          socket.roomDbId = roomDbId;
          const ownerResult = await pool.query('SELECT owner_id FROM rooms WHERE id = $1', [roomDbId]);
          socket.isOwner = (ownerResult.rows[0].owner_id === socket.userId);

          if (socket.isOwner) {
            joinWsRoom(socket, roomDbId);
            socket.send(JSON.stringify({ type: 'system', text: '✅ 房主进入房间' }));
          } else {
            const appResult = await pool.query('SELECT * FROM applications WHERE room_id = $1 AND applicant_id = $2', [roomDbId, socket.userId]);
            const app = appResult.rows[0];
            
            if (!app) {
              await pool.query('INSERT INTO applications (room_id, applicant_id) VALUES ($1, $2)', [roomDbId, socket.userId]);
              notifyOwner(ownerResult.rows[0].owner_id, roomDbId, socket.username);
              socket.send(JSON.stringify({ type: 'system', text: '📩 申请已提交，等待房主审核...' }));
            } else {
              if (app.status === 'approved') {
                joinWsRoom(socket, roomDbId);
                socket.send(JSON.stringify({ type: 'system', text: '✅ 已批准，欢迎加入！' }));
              } else if (app.status === 'pending') {
                socket.send(JSON.stringify({ type: 'system', text: '⏳ 你的申请正在审核中...' }));
              } else {
                socket.send(JSON.stringify({ type: 'system', text: '❌ 你的申请已被拒绝' }));
              }
            }
          }
        }
      }

      if (msg.type === 'msg') {
        if (!socket.roomDbId) return;
        const room = wsRooms.get(socket.roomDbId);
        if (!room) return;
        room.forEach(client => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
              type: 'msg',
              text: msg.text,
              sender: socket.username,
              time: new Date().toLocaleTimeString()
            }));
          }
        });
      }
    } catch (e) {
      console.error('消息处理错误:', e);
    }
  });

  socket.on('close', () => {
    if (socket.roomDbId) {
      const room = wsRooms.get(socket.roomDbId);
      if (room) {
        room.delete(socket);
        if (room.size === 0) wsRooms.delete(socket.roomDbId);
      }
    }
    console.log(`👋 ${socket.username} 断开连接`);
  });
});

function joinWsRoom(socket, roomDbId) {
  if (socket.wsRoomId) {
    const oldRoom = wsRooms.get(socket.wsRoomId);
    if (oldRoom) {
      oldRoom.delete(socket);
      if (oldRoom.size === 0) wsRooms.delete(socket.wsRoomId);
    }
  }
  socket.wsRoomId = roomDbId;
  if (!wsRooms.has(roomDbId)) wsRooms.set(roomDbId, new Set());
  wsRooms.get(roomDbId).add(socket);
  
  wsRooms.get(roomDbId).forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'system', text: `👤 ${socket.username} 加入了房间` }));
    }
  });
}

function notifyOwner(ownerId, roomDbId, applicantName) {
  wss.clients.forEach(client => {
    if (client.userId === ownerId && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'new_application', roomDbId, applicant: applicantName }));
    }
  });
}

// ==================== 启动服务 ====================
const PORT = process.env.PORT || 3000;

// 先初始化数据库，再启动服务
initDB().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 服务器已启动: http://0.0.0.0:${PORT}`);
    console.log(`🌐 环境: ${process.env.NODE_ENV || 'development'}`);
  });
}).catch(err => {
  console.error('❌ 服务启动失败:', err);
  process.exit(1);
});
