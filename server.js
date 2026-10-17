require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'QuangHoang_Admin_2026';

app.use(cors());
app.use(express.json());

// Phục vụ tĩnh 2 Webapp
app.use('/app', express.static(path.join(__dirname, 'public/client')));
app.use('/admin', express.static(path.join(__dirname, 'public/admin')));

// Đảm bảo thư mục dữ liệu và các tệp lưu trữ tồn tại
const dataDir = path.join(__dirname, 'data');
const dbPath = path.join(dataDir, 'db.json');
const hexRefPath = path.join(dataDir, 'hex_reference.txt');

if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(dbPath)) {
  fs.writeFileSync(dbPath, JSON.stringify({ keys: [], configs: {}, logs: [] }, null, 2));
}
if (!fs.existsSync(hexRefPath)) {
  fs.writeFileSync(
    hexRefPath,
    '4845585F5245464552454E43455F5350465F484F414E475F53494D554C4154494F4E5F4F4E4C59'
  );
}

// Hàm đọc/ghi tệp db.json
function readDB() {
  try {
    return JSON.parse(fs.readFileSync(dbPath, 'utf-8'));
  } catch {
    return { keys: [], configs: {}, logs: [] };
  }
}

function writeDB(data) {
  fs.writeFileSync(dbPath, JSON.stringify(data, null, 2));
}

function addAuditLog(action, detail) {
  const db = readDB();
  if (!Array.isArray(db.logs)) db.logs = [];
  db.logs.unshift({
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    action,
    detail
  });
  db.logs = db.logs.slice(0, 100);
  writeDB(db);
}

// Lưu trữ phiên làm việc
const adminSessions = new Set();
const userSessions = new Map();

const DURATION_MAP = {
  '1h': { label: '1 giờ', ms: 60 * 60 * 1000 },
  '1d': { label: '1 ngày', ms: 24 * 60 * 60 * 1000 },
  '7d': { label: '7 ngày', ms: 7 * 24 * 60 * 60 * 1000 },
  '1m': { label: '1 tháng', ms: 30 * 24 * 60 * 60 * 1000 },
  '1y': { label: '1 năm', ms: 365 * 24 * 60 * 60 * 1000 },
  'forever': { label: 'Vĩnh viễn', ms: null }
};

function evaluateKeyStatus(keyRecord) {
  if (keyRecord.revoked) return 'revoked';
  if (keyRecord.expiresAt !== null && Date.now() > keyRecord.expiresAt) {
    return 'expired';
  }
  return 'active';
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { success: false, message: 'Quá nhiều yêu cầu. Vui lòng thử lại sau 15 phút.' }
});

function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (!token || !adminSessions.has(token)) {
    return res.status(401).json({ success: false, message: 'Không có quyền truy cập quản trị.' });
  }
  next();
}

function requireUserSession(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '').trim();
  const session = userSessions.get(token);

  if (!session) {
    return res.status(401).json({ success: false, message: 'Phiên đăng nhập không hợp lệ.' });
  }

  const db = readDB();
  const keyRecord = (db.keys || []).find(k => k.key === session.keyString);
  if (!keyRecord) {
    userSessions.delete(token);
    return res.status(401).json({ success: false, message: 'Key không tồn tại.' });
  }

  const currentStatus = evaluateKeyStatus(keyRecord);
  if (currentStatus !== 'active') {
    userSessions.delete(token);
    return res.status(403).json({
      success: false,
      status: currentStatus,
      message: currentStatus === 'revoked' ? 'Key đã bị thu hồi.' : 'Key đã hết hạn sử dụng.'
    });
  }

  req.userKey = keyRecord.key;
  next();
}

/* ================= API QUẢN TRỊ VIÊN ================= */

app.post('/api/admin/login', authLimiter, (req, res) => {
  const { password } = req.body;
  if (!password || password !== ADMIN_PASSWORD) {
    addAuditLog('ADMIN_LOGIN_FAILED', 'Nhập sai mật khẩu quản trị');
    return res.status(401).json({ success: false, message: 'Mật khẩu quản trị không chính xác.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.add(token);
  addAuditLog('ADMIN_LOGIN_SUCCESS', 'Quản trị viên đăng nhập thành công');
  res.json({ success: true, token });
});

app.get('/api/admin/keys', requireAdmin, (req, res) => {
  const db = readDB();
  const enrichedKeys = (db.keys || []).map(k => ({
    ...k,
    status: evaluateKeyStatus(k)
  }));
  res.json({ success: true, keys: enrichedKeys, logs: (db.logs || []).slice(0, 30) });
});

app.post('/api/admin/keys/create', requireAdmin, authLimiter, (req, res) => {
  const { durationCode } = req.body;
  const durationInfo = DURATION_MAP[durationCode];

  if (!durationInfo) {
    return res.status(400).json({ success: false, message: 'Thời hạn key không hợp lệ.' });
  }

  const db = readDB();
  if (!Array.isArray(db.keys)) db.keys = [];

  let newKey = '';
  do {
    const p1 = crypto.randomBytes(3).toString('hex').toUpperCase();
    const p2 = crypto.randomBytes(3).toString('hex').toUpperCase();
    const p3 = crypto.randomBytes(3).toString('hex').toUpperCase();
    newKey = `SPF-${p1}-${p2}-${p3}`;
  } while (db.keys.some(k => k.key === newKey));

  const now = Date.now();
  const expiresAt = durationInfo.ms ? now + durationInfo.ms : null;

  const keyRecord = {
    id: crypto.randomUUID(),
    key: newKey,
    durationCode,
    durationLabel: durationInfo.label,
    createdAt: now,
    expiresAt,
    revoked: false
  };

  db.keys.unshift(keyRecord);
  writeDB(db);
  addAuditLog('KEY_CREATED', `Tạo key ${newKey} (${durationInfo.label})`);

  res.json({
    success: true,
    message: 'Tạo key mới thành công.',
    keyData: { ...keyRecord, status: 'active' }
  });
});

app.post('/api/admin/keys/revoke', requireAdmin, (req, res) => {
  const { id } = req.body;
  const db = readDB();
  const target = (db.keys || []).find(k => k.id === id);

  if (!target) {
    return res.status(404).json({ success: false, message: 'Không tìm thấy key.' });
  }

  target.revoked = true;
  writeDB(db);
  addAuditLog('KEY_REVOKED', `Thu hồi key ${target.key}`);

  res.json({ success: true, message: `Đã thu hồi key ${target.key}.` });
});

/* ================= API NGƯỜI DÙNG ================= */

app.post('/api/client/verify-key', authLimiter, (req, res) => {
  const { key } = req.body;
  if (!key || typeof key !== 'string') {
    return res.status(400).json({ success: false, status: 'invalid', message: 'Vui lòng nhập mã key.' });
  }

  const normalizedKey = key.trim().toUpperCase();
  const db = readDB();
  const keyRecord = (db.keys || []).find(k => k.key === normalizedKey);

  if (!keyRecord) {
    return res.status(404).json({
      success: false,
      status: 'invalid',
      message: 'Key không hợp lệ hoặc không tồn tại.'
    });
  }

  const status = evaluateKeyStatus(keyRecord);
  if (status === 'revoked') {
    return res.status(403).json({
      success: false,
      status: 'revoked',
      message: 'Key này đã bị quản trị viên thu hồi.'
    });
  }
  if (status === 'expired') {
    return res.status(403).json({
      success: false,
      status: 'expired',
      message: 'Key đã hết hạn sử dụng.'
    });
  }

  const sessionToken = crypto.randomBytes(24).toString('hex');
  userSessions.set(sessionToken, {
    keyString: keyRecord.key,
    expiresAt: keyRecord.expiresAt
  });

  const savedConfig = (db.configs && db.configs[keyRecord.key]) || null;

  res.json({
    success: true,
    status: 'active',
    message: 'Xác thực key hợp lệ!',
    sessionToken,
    keyInfo: {
      key: keyRecord.key,
      durationLabel: keyRecord.durationLabel,
      createdAt: keyRecord.createdAt,
      expiresAt: keyRecord.expiresAt
    },
    savedConfig
  });
});

app.post('/api/client/config', requireUserSession, (req, res) => {
  const { features, optimizer } = req.body;
  const db = readDB();
  if (!db.configs) db.configs = {};

  db.configs[req.userKey] = {
    updatedAt: Date.now(),
    features: features || {},
    optimizer: typeof optimizer === 'number' ? Math.min(100, Math.max(0, optimizer)) : 50
  };
  writeDB(db);
  res.json({ success: true, message: 'Đã lưu cấu hình mô phỏng.' });
});

app.get('/api/client/hex-reference', requireUserSession, (req, res) => {
  const rawHex = fs.readFileSync(hexRefPath, 'utf-8').trim();
  const isValidHex = /^[0-9A-Fa-f\s]+$/.test(rawHex);
  const sha256 = crypto.createHash('sha256').update(rawHex).digest('hex');

  let decodedPreview = '';
  if (isValidHex) {
    try {
      const cleanHex = rawHex.replace(/\s+/g, '');
      decodedPreview = Buffer.from(cleanHex.slice(0, 200), 'hex').toString('utf-8');
    } catch {
      decodedPreview = 'Không thể giải mã UTF-8';
    }
  }

  res.json({
    success: true,
    integrity: {
      isValidHex,
      byteLength: Math.floor(rawHex.replace(/\s+/g, '').length / 2),
      sha256
    },
    rawHexPreview: rawHex.slice(0, 512),
    decodedPreview
  });
});

app.listen(PORT, () => {
  console.log(`========================================`);
  console.log(`Hệ thống đã khởi chạy thành công:`);
  console.log(`- Webapp Spf_Hoang:  http://localhost:${PORT}/app`);
  console.log(`- Webapp Quản trị:   http://localhost:${PORT}/admin`);
  console.log(`========================================`);
});