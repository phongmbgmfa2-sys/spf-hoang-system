const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'quanghoang123';
const SECRET_SALT = 'spf_hoang_secret_2026';
const DATA_FILE = path.join(__dirname, 'keys-data.json');

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

let keysStore = {};
let revokedKeys = new Set();

function loadKeysFromDisk() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      keysStore = raw.keysStore || raw || {};
      revokedKeys = new Set(raw.revokedKeys || []);
    }
  } catch (err) {
    keysStore = {};
    revokedKeys = new Set();
  }
}

function saveKeysToDisk() {
  try {
    fs.writeFileSync(
      DATA_FILE,
      JSON.stringify({ keysStore, revokedKeys: Array.from(revokedKeys) }, null, 2),
      'utf8'
    );
  } catch (err) {}
}

loadKeysFromDisk();

const DURATION_MAP = {
  '1h': { label: '1 Giờ', ms: 1 * 60 * 60 * 1000 },
  '2h': { label: '2 Giờ', ms: 2 * 60 * 60 * 1000 },
  '5h': { label: '5 Giờ', ms: 5 * 60 * 60 * 1000 },
  '1d': { label: '1 Ngày', ms: 24 * 60 * 60 * 1000 },
  '1w': { label: '1 Tuần', ms: 7 * 24 * 60 * 60 * 1000 },
  '2w': { label: '2 Tuần', ms: 14 * 24 * 60 * 60 * 1000 },
  '1m': { label: '1 Tháng', ms: 30 * 24 * 60 * 60 * 1000 },
  '2m': { label: '2 Tháng', ms: 60 * 24 * 60 * 1000 },
  '1y': { label: '1 Năm', ms: 365 * 24 * 60 * 60 * 1000 },
  'forever': { label: 'Vĩnh viễn', ms: null }
};

// Token Admin cố định theo mật khẩu để không bị văng khi Render khởi động lại
function getStaticAdminToken() {
  return crypto.createHmac('sha256', SECRET_SALT).update(ADMIN_PASSWORD).digest('hex');
}

function generateFormattedKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = () => Array.from({ length: 6 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  return `SPF-${seg()}-${seg()}-${seg()}`;
}

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token || token !== getStaticAdminToken()) {
    return res.status(401).json({ success: false, message: 'Phiên Admin hết hạn. Vui lòng đăng nhập lại.' });
  }
  next();
}

app.get('/api/ping', (req, res) => {
  res.json({ ok: true, time: Date.now() });
});

// ================= API ADMIN =================
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body || {};
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Mật khẩu Admin không đúng!' });
  }
  res.json({ success: true, token: getStaticAdminToken() });
});

app.get('/api/admin/keys', requireAdmin, (req, res) => {
  const now = Date.now();
  const list = Object.values(keysStore)
    .map(k => ({
      ...k,
      isExpired: k.expiresAt ? now > k.expiresAt : false
    }))
    .sort((a, b) => b.createdAt - a.createdAt);
  res.json({ success: true, keys: list });
});

app.post('/api/admin/sync-restore', requireAdmin, (req, res) => {
  const { backupKeys } = req.body || {};
  let restoredCount = 0;
  if (Array.isArray(backupKeys)) {
    backupKeys.forEach(item => {
      if (item && item.key && !keysStore[item.key] && !revokedKeys.has(item.key)) {
        keysStore[item.key] = item;
        restoredCount++;
      }
    });
    if (restoredCount > 0) saveKeysToDisk();
  }
  res.json({ success: true, restoredCount, total: Object.keys(keysStore).length });
});

app.post('/api/admin/generate-key', requireAdmin, (req, res) => {
  const { durationCode, note } = req.body || {};
  const d = DURATION_MAP[durationCode] || DURATION_MAP['1d'];
  const newKey = generateFormattedKey();
  const now = Date.now();

  const record = {
    key: newKey,
    durationCode: durationCode || '1d',
    durationLabel: d.label,
    createdAt: now,
    expiresAt: d.ms ? now + d.ms : null,
    note: (note || '').trim(),
    boundDeviceId: null,
    boundDeviceName: null,
    boundAt: null,
    savedConfig: null
  };

  revokedKeys.delete(newKey);
  keysStore[newKey] = record;
  saveKeysToDisk();
  res.json({ success: true, keyData: record });
});

app.delete('/api/admin/keys/:key', requireAdmin, (req, res) => {
  const targetKey = (req.params.key || '').trim().toUpperCase();
  delete keysStore[targetKey];
  revokedKeys.add(targetKey);
  saveKeysToDisk();
  res.json({ success: true, message: `Đã xoá Key ${targetKey} khỏi hệ thống.` });
});

app.post('/api/admin/cleanup-expired', requireAdmin, (req, res) => {
  const now = Date.now();
  let deletedCount = 0;
  Object.keys(keysStore).forEach(k => {
    const item = keysStore[k];
    if (item.expiresAt && now > item.expiresAt) {
      delete keysStore[k];
      revokedKeys.add(k);
      deletedCount++;
    }
  });
  saveKeysToDisk();
  res.json({ success: true, deletedCount, message: `Đã dọn dẹp ${deletedCount} Key hết hạn!` });
});

// ================= API CLIENT =================
app.post('/api/client/verify-key', (req, res) => {
  const { key, deviceId, deviceName } = req.body || {};
  const cleanKey = (key || '').trim().toUpperCase();

  if (!cleanKey) {
    return res.status(400).json({ success: false, message: 'Vui lòng nhập mã Key!' });
  }

  if (revokedKeys.has(cleanKey)) {
    return res.status(403).json({ success: false, message: 'Mã Key này đã bị Admin xoá!' });
  }

  // Nếu Render vừa khởi động lại làm trống RAM nhưng Key đúng chuẩn SPF-XXXXXX-XXXXXX-XXXXXX, tự động khôi phục
  const isValidFormat = /^SPF-[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{6}$/.test(cleanKey);
  if (!keysStore[cleanKey] && isValidFormat) {
    const now = Date.now();
    keysStore[cleanKey] = {
      key: cleanKey,
      durationCode: '1d',
      durationLabel: 'VIP Active',
      createdAt: now,
      expiresAt: now + 24 * 60 * 60 * 1000,
      note: 'Tự động khôi phục sau khi Server khởi động lại',
      boundDeviceId: null,
      boundDeviceName: null,
      boundAt: null,
      savedConfig: null
    };
    saveKeysToDisk();
  }

  if (!keysStore[cleanKey]) {
    return res.status(404).json({
      success: false,
      message: 'Mã Key không đúng định dạng (VD: SPF-XXXXXX-XXXXXX-XXXXXX) hoặc không tồn tại!'
    });
  }

  const record = keysStore[cleanKey];
  const now = Date.now();

  if (record.expiresAt && now > record.expiresAt) {
    return res.status(403).json({ success: false, message: 'Mã Key này đã hết hạn sử dụng!' });
  }

  if (record.boundDeviceId && deviceId && record.boundDeviceId !== deviceId) {
    return res.status(403).json({
      success: false,
      message: `Key này đã được kích hoạt trên thiết bị khác (${record.boundDeviceName || 'Máy đầu tiên'})!`
    });
  }

  if (!record.boundDeviceId && deviceId) {
    record.boundDeviceId = deviceId;
    record.boundDeviceName = deviceName || 'Thiết bị di động';
    record.boundAt = now;
    saveKeysToDisk();
  }

  res.json({
    success: true,
    message: 'Xác thực Key thành công! Đang mở bảng điều khiển...',
    sessionToken: cleanKey,
    keyInfo: {
      key: record.key,
      durationLabel: record.durationLabel || 'VIP',
      expiresAt: record.expiresAt
    },
    savedConfig: record.savedConfig
  });
});

app.post('/api/client/config', (req, res) => {
  const auth = req.headers.authorization || '';
  const cleanKey = auth.replace('Bearer ', '').trim().toUpperCase();

  if (!cleanKey || !keysStore[cleanKey]) {
    return res.json({ success: true });
  }

  keysStore[cleanKey].savedConfig = {
    features: req.body.features || {},
    optimizer: req.body.optimizer ?? 95,
    updatedAt: Date.now()
  };
  saveKeysToDisk();
  res.json({ success: true });
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html'));
});

app.get(['/', '/app'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'client', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Spf_Hoang Server running on port ${PORT}`);
});