// logger.js - Railway 专用日志解决方案
'use strict';

// ======== 1. 立即禁用 stdout 缓冲（Railway 关键！） ========
process.stdout._handle.setBlocking(true);
process.stderr._handle.setBlocking(true);

// 确保日志立即刷新
const flushLogs = () => {
  try {
    process.stdout.write('');
    process.stderr.write('');
  } catch (e) {
    // 忽略错误（可能在退出时）
  }
};

// 每 100ms 强制刷新日志
setInterval(flushLogs, 100).unref();

// ======== 2. 创建 Railway 优化的日志器 ========
class RailwayLogger {
  constructor() {
    this.levels = {
      'error': 0,
      'warn': 1,
      'info': 2,
      'debug': 3
    };
    
    this.currentLevel = this.levels[process.env.LOG_LEVEL || 'info'];
    this.colors = this._supportsColor() ? {
      reset: "\x1b[0m",
      cyan: "\x1b[36m",
      yellow: "\x1b[33m",
      red: "\x1b[31m",
      green: "\x1b[32m",
      blue: "\x1b[34m"
    } : {
      reset: "",
      cyan: "",
      yellow: "",
      red: "",
      green: "",
      blue: ""
    };
  }

  _supportsColor() {
    return process.stdout.isTTY && 
           process.env.FORCE_COLOR !== '0' &&
           process.env.RAILWAY !== '1'; // Railway 不需要颜色
  }

  _getTime() {
    const now = new Date();
    return `${now.toISOString().replace('T', ' ').substring(0, 19)}`;
  }

  _shouldLog(level) {
    return this.levels[level] <= this.currentLevel;
  }

  _log(level, color, ...args) {
    if (!this._shouldLog(level)) return;
    
    // Railway 需要纯文本（无颜色）
    const prefix = process.env.RAILWAY ? 
      `[${level.toUpperCase()}]` : 
      `${this.colors[color]}[${level.toUpperCase()}]${this.colors.reset}`;
    
    const timestamp = this._getTime();
    
    // 确保立即写入
    process.stdout.write(
      `${timestamp} ${prefix} ${args.map(arg => 
        typeof arg === 'object' ? JSON.stringify(arg) : arg
      ).join(' ')}\n`
    );
    
    flushLogs();
  }

  error(...args) {
    this._log('error', 'red', ...args);
  }

  warn(...args) {
    this._log('warn', 'yellow', ...args);
  }

  info(...args) {
    this._log('info', 'green', ...args);
  }

  debug(...args) {
    this._log('debug', 'blue', ...args);
  }
}

// ======== 3. 创建单例并立即测试 ========
const logger = new RailwayLogger();

// 关键！立即输出测试日志（必须在 require 任何模块前）
logger.info('✅ Railway 日志系统已初始化 - 立即可见');
logger.warn('⚠️ 测试警告 - 部署后应立即在 Logs 中可见');
logger.error('❌ 测试错误 - 验证错误日志是否工作');

// 每秒输出心跳日志（验证日志流）
setInterval(() => {
  logger.debug('💓 心跳日志 - 确保日志系统活跃');
}, 1000).unref();

module.exports = logger;
