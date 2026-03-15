require('dotenv').config();
const http = require('http');
const express = require('express');
const WebSocket = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

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
// 健康检查端点 - 必须！
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok',
    timestamp: new Date().toISOString(),
    port: process.env.PORT || 8080
  });
  
  // 添加日志便于诊断
  console.log('🏥 健康检查请求 - 状态: 200');
});

// 可选：更严格的健康检查
app.get('/ready', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.status(200).json({ status: 'ready', db: 'connected' });
  } catch (err) {
    console.error('❌ 健康检查失败:', err);
    res.status(503).json({ status: 'unhealthy', error: err.message });
  }
});
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

  console.log('🔌 尝试连接数据库:', connectionString.replace(/:([^:]+)@/, ':****@'));
  
  pool = new Pool({
    connectionString: connectionString,
    ssl: {
      rejectUnauthorized: false // Railway 必需
    },
    connectionTimeoutMillis: 5000,
    max: 20 // 连接池大小
  });

  // 添加错误处理
  pool.on('error', (err) => {
    console.error('❌ 数据库连接池错误:', err);
    pool = null;
  });

  return pool;
}

// 增强的数据库连接重试逻辑
async function connectWithRetry(maxRetries = 5, delay = 3000) {
  let attempts = 0;
  
  while (attempts < maxRetries) {
    try {
      const pool = createPool();
      await pool.query('SELECT NOW()');
      console.log('✅ 数据库连接成功！');
      return pool;
    } catch (err) {
      attempts++;
      console.error(`❌ 数据库连接失败 (尝试 ${attempts}/${maxRetries}):`, 
        err.message || err.code);
      
      if (attempts >= maxRetries) {
        console.error('🛑 达到最大重试次数，无法连接数据库');
        throw err;
      }
      
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// ==================== 初始化数据库 ====================
async function initDB() {
  try {
    // 使用重试逻辑连接数据库
    await connectWithRetry(10, 5000);
    console.log('🔍 开始初始化数据库表...');
    
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

    // ... 其余表创建代码保持不变 ...
    
    console.log('✅ 数据库表已初始化');
    
    // 检查并创建管理员（如果不存在）
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
    console.error('❌ 数据库初始化错误:', err);
    // 添加更详细的错误信息
    if (err.code === 'ECONNREFUSED') {
      console.error(`
      ===========================================
      数据库连接被拒绝！请检查：
      1. 是否已在 Railway 添加 PostgreSQL 服务？
      2. 数据库服务是否与应用服务已连接？
      3. 是否在 Variables 中看到 DATABASE_URL 变量？
      ===========================================
      `);
    }
    throw err; // 确保错误被抛出，以便正确处理
  }
}

// ==================== JWT 认证中间件 ====================
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: '未提供认证令牌' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, async (err, user) => {
    if (err) return res.status(403).json({ error: '无效的令牌' });
    
    // 验证用户是否存在
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

// ==================== 管理员认证中间件 ====================
const adminOnly = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: '需要管理员权限' });
  }
  next();
};

// ==================== API 路由 ====================

// 生成邀请码 (管理员)
app.post('/admin/generate-invite', authenticateJWT, adminOnly, async (req, res) => {
  try {
    const code = Math.random().toString(36).substring(2, 10).toUpperCase();
    
    await pool.query(
      'INSERT INTO invite_codes (code) VALUES ($1)', 
      [code]
    );
    
    console.log(`🛡️ 管理员 ${req.user.username} 生成了邀请码: ${code}`);
    res.json({ 
      inviteCode: code,
      expiresIn: "24小时",
      message: "邀请码24小时内有效"
    });
  } catch (err) {
    console.error('生成邀请码错误:', err);
    res.status(500).json({ error: '生成失败' });
  }
});

// 查看邀请码列表 (管理员)
app.get('/admin/invite-codes', authenticateJWT, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, code, used, 
             created_at AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Shanghai' as created_at,
             used_at AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Shanghai' as used_at,
             (SELECT username FROM users WHERE id = used_by) as used_by
      FROM invite_codes
      ORDER BY created_at DESC
      LIMIT 50
    `);
    
    res.json(result.rows);
  } catch (err) {
    console.error('查询邀请码错误:', err);
    res.status(500).json({ error: '查询失败' });
  }
});

// 用户注册
app.post('/register', async (req, res) => {
  const { username, password, inviteCode } = req.body;
  if (!username || !password || !inviteCode) {
    return res.status(400).json({ error: '缺少必要参数' });
  }

  try {
    // 检查邀请码
    const inviteResult = await pool.query(
      'SELECT * FROM invite_codes WHERE code = $1 AND used = false', 
      [inviteCode]
    );
    
    if (inviteResult.rows.length === 0) {
      return res.status(400).json({ error: '邀请码无效或已使用' });
    }

    // 检查用户名
    const userResult = await pool.query(
      'SELECT id FROM users WHERE username = $1', 
      [username]
    );
    
    if (userResult.rows.length > 0) {
      return res.status(400).json({ error: '用户名已被占用' });
    }

    // 创建用户
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const userResult2 = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id',
      [username, passwordHash]
    );
    
    const userId = userResult2.rows[0].id;
    
    // 标记邀请码为已使用
    await pool.query(
      `UPDATE invite_codes 
       SET used = true, 
           used_by = $1, 
           used_at = CURRENT_TIMESTAMP 
       WHERE id = $2`,
      [userId, inviteResult.rows[0].id]
    );

    // 生成 JWT
    const token = jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
  } catch (err) {
    console.error('注册错误:', err);
    res.status(500).json({ error: '注册失败' });
  }
});

// 用户登录
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

    // 更新最后登录时间
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

// 获取我的房间
app.get('/my-rooms', authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        r.id, 
        r.room_id, 
        r.created_at,
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
    console.error('获取房间错误:', err);
    res.status(500).json({ error: '数据库错误' });
  }
});

// 审核申请 - 批准
app.post('/applications/:appId/approve', authenticateJWT, async (req, res) => {
  const appId = req.params.appId;
  const userId = req.user.id;

  try {
    // 验证权限
    const result = await pool.query(`
      SELECT a.*, r.owner_id 
      FROM applications a
      JOIN rooms r ON a.room_id = r.id
      WHERE a.id = $1
    `, [appId]);
    
    const app = result.rows[0];
    if (!app || app.owner_id !== userId) {
      return res.status(403).json({ error: '无权限' });
    }

    // 更新申请状态
    await pool.query(`
      UPDATE applications 
      SET status = 'approved', responded_at = CURRENT_TIMESTAMP 
      WHERE id = $1
    `, [appId]);

    // 通知申请人
    wss.clients.forEach(client => {
      if (client.userId === app.applicant_id && client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({
          type: 'application_approved',
          roomDbId: app.room_id
        }));
      }
    });
    
    res.json({ success: true });
  } catch (err) {
    console.error('批准申请错误:', err);
    res.status(500).json({ error: '操作失败' });
  }
});

// 审核申请 - 拒绝
app.post('/applications/:appId/reject', authenticateJWT, async (req, res) => {
  const appId = req.params.appId;
  const userId = req.user.id;

  try {
    // 验证权限
    const result = await pool.query(`
      SELECT a.*, r.owner_id 
      FROM applications a
      JOIN rooms r ON a.room_id = r.id
      WHERE a.id = $1
    `, [appId]);
    
    const app = result.rows[0];
    if (!app || app.owner_id !== userId) {
      return res.status(403).json({ error: '无权限' });
    }

    // 更新申请状态
    await pool.query(`
      UPDATE applications 
      SET status = 'rejected', responded_at = CURRENT_TIMESTAMP 
      WHERE id = $1
    `, [appId]);

    // 通知申请人
    wss.clients.forEach(client => {
      if (client.userId === app.applicant_id && client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({
          type: 'application_rejected'
        }));
      }
    });
    
    res.json({ success: true });
  } catch (err) {
    console.error('拒绝申请错误:', err);
    res.status(500).json({ error: '操作失败' });
  }
});

// 查看我的申请
app.get('/my-applications', authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT a.id, a.room_id, a.status, a.created_at, 
             u.username AS applicant_name
      FROM applications a
      JOIN users u ON a.applicant_id = u.id
      WHERE a.room_id IN (
        SELECT id FROM rooms WHERE owner_id = $1
      ) AND a.status = 'pending'
    `, [req.user.id]);
    
    res.json(result.rows);
  } catch (err) {
    console.error('获取申请错误:', err);
    res.status(500).json({ error: '查询失败' });
  }
});

// ==================== WebSocket 逻辑 ====================
const wsRooms = new Map(); // key: roomDbId, value: Set<socket>

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
    
    // 获取用户详细信息
    const result = await pool.query(
      'SELECT id, username FROM users WHERE id = $1', 
      [user.userId]
    );
    
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

      // 房主直接进入自己房间
      if (msg.type === 'join-as-owner') {
        const { roomIdHash } = msg;
        const fullHash = roomIdHash.replace('…', '');

        const result = await pool.query(
          'SELECT * FROM rooms WHERE room_id LIKE $1', 
          [fullHash + '%']
        );
        
        const room = result.rows[0];
        if (!room) {
          return socket.send(JSON.stringify({ type: 'error', text: '房间不存在' }));
        }

        // 验证是否为房主
        const ownerResult = await pool.query(
          'SELECT owner_id FROM rooms WHERE id = $1', 
          [room.id]
        );
        
        if (ownerResult.rows[0].owner_id !== socket.userId) {
          return socket.send(JSON.stringify({ type: 'error', text: '无权限进入' }));
        }

        socket.roomDbId = room.id;
        socket.isOwner = true;
        joinWsRoom(socket, room.id);

        socket.send(JSON.stringify({
          type: 'system',
          text: `✅ 已进入你的房间【${roomIdHash}】`
        }));
        return;
      }

      // 加入房间
      if (msg.type === 'join') {
        const { password } = msg;
        const roomIdHash = require('crypto')
          .createHash('sha256')
          .update(password + SALT)
          .digest('hex')
          .slice(0, 16);

        const roomResult = await pool.query(
          'SELECT * FROM rooms WHERE room_id = $1', 
          [roomIdHash]
        );
        
        const room = roomResult.rows[0];

        // 情况1：房间不存在 → 创建房间
        if (!room) {
          const result = await pool.query(
            'INSERT INTO rooms (room_id, owner_id) VALUES ($1, $2) RETURNING id',
            [roomIdHash, socket.userId]
          );
          
          const newRoomId = result.rows[0].id;
          socket.roomDbId = newRoomId;
          socket.isOwner = true;

          wsRooms.set(newRoomId, new Set());
          wsRooms.get(newRoomId).add(socket);

          socket.send(JSON.stringify({
            type: 'system',
            text: `✅ 你已成为房间【${roomIdHash.slice(0,8)}】的房主！`
          }));
        }
        // 情况2：房间已存在
        else {
          const roomDbId = room.id;
          socket.roomDbId = roomDbId;
          
          // 检查是否为房主
          const ownerResult = await pool.query(
            'SELECT owner_id FROM rooms WHERE id = $1', 
            [roomDbId]
          );
          
          socket.isOwner = (ownerResult.rows[0].owner_id === socket.userId);

          if (socket.isOwner) {
            joinWsRoom(socket, roomDbId);
            socket.send(JSON.stringify({ type: 'system', text: '✅ 房主进入房间' }));
          }
          else {
            const appResult = await pool.query(
              'SELECT * FROM applications WHERE room_id = $1 AND applicant_id = $2',
              [roomDbId, socket.userId]
            );
            
            const app = appResult.rows[0];
            
            if (!app) {
              await pool.query(
                'INSERT INTO applications (room_id, applicant_id) VALUES ($1, $2)',
                [roomDbId, socket.userId]
              );

              // 通知房主
              notifyOwner(ownerResult.rows[0].owner_id, roomDbId, socket.username);
              
              socket.send(JSON.stringify({
                type: 'system',
                text: '📩 申请已提交，等待房主审核...'
              }));
            }
            else {
              if (app.status === 'approved') {
                joinWsRoom(socket, roomDbId);
                socket.send(JSON.stringify({
                  type: 'system',
                  text: '✅ 已批准，欢迎加入！'
                }));
              } else if (app.status === 'pending') {
                socket.send(JSON.stringify({
                  type: 'system',
                  text: '⏳ 你的申请正在审核中...'
                }));
              } else {
                socket.send(JSON.stringify({
                  type: 'system',
                  text: '❌ 你的申请已被拒绝，无法加入'
                }));
              }
            }
          }
        }
      }

      // 发送消息
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

// ==================== 辅助函数 ====================
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
      client.send(JSON.stringify({
        type: 'system',
        text: `👤 ${socket.username} 加入了房间`
      }));
    }
  });
}

function notifyOwner(ownerId, roomDbId, applicantName) {
  wss.clients.forEach(client => {
    if (client.userId === ownerId && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({
        type: 'new_application',
        roomDbId: roomDbId,
        applicant: applicantName
      }));
    }
  });
}

// ==================== 启动服务器 ====================
const PORT = process.env.PORT || 3000;

initDB().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 服务器已启动: http://0.0.0.0:${PORT}`);
  console.log(`🌐 可通过 ${process.env.RAILWAY_STATIC_URL || '外部URL'} 访问`);
});
});
