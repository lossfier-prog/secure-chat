// logger.js - Railway 安全版
'use strict';

const isRailway = !!process.env.RAILWAY_PROJECT_ID || process.stdout.isTTY;

class SimpleLogger {
  constructor() {
    this.flushTimer = null;
  }

  _getTime() {
    return new Date().toISOString();
  }

  _write(level, ...args) {
    const timestamp = this._getTime();
    const message = args.map(arg => 
      typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
    ).join(' ');
    
    const line = `${timestamp} [${level.toUpperCase()}] ${message}\n`;
    
    try {
      // 直接写入 stdout（不缓冲）
      process.stdout.write(line);
      
      // 立即刷新
      if (this.flushTimer) clearTimeout(this.flushTimer);
      this.flushTimer = setTimeout(() => {
        try { process.stdout.write(''); } catch(e) {}
      }, 10).unref();
    } catch (writeErr) {
      // 写入失败时尝试 stderr
      try { process.stderr.write(`[WRITE_ERROR] ${writeErr.message}\n`); } catch(e) {}
    }
  }

  info(...args) { this._write('info', ...args); }
  warn(...args) { this._write('warn', ...args); }
  error(...args) { this._write('error', ...args); }
  debug(...args) { if (process.env.DEBUG !== 'false') this._write('debug', ...args); }
}

// 立即测试日志系统
const logger = new SimpleLogger();
logger.info('✅ 安全日志系统已初始化');

module.exports = logger;
