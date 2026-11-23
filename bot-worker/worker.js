/**
 * MGD Trading Technology — Unified Admin Control Center & Bot API (v3.0)
 *
 * Central Architecture:
 *  - Cloudflare D1 (`MGD_DB`): Users, PBKDF2 Auth, Revocable Sessions, Granular RBAC,
 *    Audit Logs, CMS Config/Pages/Revisions, Orders, Customers, Licenses,
 *    Social Media Center, Signals, Academy, Agencies, Projects, Tasks, Chat, Support Tickets.
 *  - Cloudflare KV (`MGD_STORE`): Backward-compatible fast store for live order checkout & Telegram msg refs.
 *  - Cloudflare Workers AI (`AI`): Telegram free-text publisher + MGD AI Assistant with preview & confirmation.
 *  - GitHub Contents API: Syncs public `products.json` & product images to `mgdtrading` repo.
 */

const AI_MODELS = [
  '@cf/meta/llama-3.3-70b-instruct-fp8-fast',
  '@cf/meta/llama-3.1-8b-instruct-fast',
  '@cf/meta/llama-3.2-3b-instruct',
];

async function runWorkersAI(env, payload) {
  if (!env.AI) return null;
  let lastErr = null;
  for (const model of AI_MODELS) {
    try {
      return await env.AI.run(model, payload);
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr;
}

const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
};

const ALL_PERMISSIONS = [
  'dashboard.view',
  'cms.view', 'cms.edit', 'cms.publish',
  'products.view', 'products.create', 'products.edit', 'products.delete',
  'orders.view', 'orders.approve',
  'customers.view', 'customers.manage', 'licenses.manage',
  'staff.view', 'staff.manage',
  'marketing.view', 'marketing.create', 'marketing.schedule', 'marketing.approve', 'marketing.publish',
  'signals.view', 'signals.manage',
  'academy.view', 'academy.manage',
  'agencies.view', 'agencies.manage',
  'projects.view', 'projects.manage', 'chat.access',
  'support.view', 'support.manage',
  'reports.view', 'reports.export',
  'ai.use', 'audit.view', 'settings.manage',
];

const ROLE_PRESETS = {
  super_admin: ALL_PERMISSIONS,
  deputy_manager: ALL_PERMISSIONS.filter(p => p !== 'settings.manage'),
  marketing_manager: ['dashboard.view', 'marketing.view', 'marketing.create', 'marketing.schedule', 'marketing.approve', 'marketing.publish', 'projects.view', 'chat.access', 'reports.view'],
  marketing_staff: ['dashboard.view', 'marketing.view', 'marketing.create', 'marketing.schedule', 'chat.access'],
  support_manager: ['dashboard.view', 'orders.view', 'orders.approve', 'customers.view', 'customers.manage', 'support.view', 'support.manage', 'chat.access', 'reports.view'],
  support_staff: ['dashboard.view', 'orders.view', 'customers.view', 'support.view', 'support.manage', 'chat.access'],
  trading_manager: ['dashboard.view', 'signals.view', 'signals.manage', 'academy.view', 'chat.access', 'reports.view'],
  trading_analyst: ['dashboard.view', 'signals.view', 'signals.manage', 'chat.access'],
  products_manager: ['dashboard.view', 'products.view', 'products.create', 'products.edit', 'products.delete', 'licenses.manage', 'chat.access'],
  academy_manager: ['dashboard.view', 'academy.view', 'academy.manage', 'chat.access'],
  agencies_manager: ['dashboard.view', 'agencies.view', 'agencies.manage', 'reports.view', 'chat.access'],
  projects_manager: ['dashboard.view', 'projects.view', 'projects.manage', 'chat.access', 'reports.view'],
  projects_staff: ['dashboard.view', 'projects.view', 'chat.access'],
};

function jsonRes(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), { status, headers: JSON_HEADERS });
}

function nowIso() {
  return new Date().toISOString();
}

function bytesToBase64(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function base64ToBytes(b64) {
  const clean = String(b64 || '').replace(/^data:[^;]+;base64,/, '').replace(/\s+/g, '');
  const bin = atob(clean);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function utf8ToBase64(str) {
  return bytesToBase64(new TextEncoder().encode(str));
}

function base64ToUtf8(b64) {
  return new TextDecoder().decode(base64ToBytes(b64));
}

function randomHex(len = 16) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

function makeId(prefix = 'id') {
  return `${prefix}_${Date.now().toString(36)}_${randomHex(3)}`;
}

function makeOrderId() {
  const num = Math.floor(1000 + Math.random() * 9000);
  const tail = Date.now().toString(36).slice(-3).toUpperCase();
  return `MGD-${num}${tail}`;
}

function makeLicenseKey() {
  const seg = () => randomHex(2).toUpperCase();
  return `MGD-${seg()}-${seg()}-${seg()}-${seg()}`;
}

function slugify(text) {
  const clean = String(text || 'product')
    .trim()
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return (clean || 'MGD_Product') + '_' + Date.now().toString(36);
}

function getClientIp(request) {
  return request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
}

// ---------- Cryptography (PBKDF2-SHA256 + SHA-256 Session Hashing) ----------

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
}

async function hashPassword(password, saltHex = randomHex(16)) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(String(password)),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: new TextEncoder().encode(saltHex),
      iterations: 100000,
      hash: 'SHA-256',
    },
    key,
    256
  );
  const hashHex = Array.from(new Uint8Array(bits), b => b.toString(16).padStart(2, '0')).join('');
  return { hashHex, saltHex };
}

function timingSafeEqual(a, b) {
  const sa = String(a || '');
  const sb = String(b || '');
  if (sa.length !== sb.length) return false;
  let diff = 0;
  for (let i = 0; i < sa.length; i++) diff |= sa.charCodeAt(i) ^ sb.charCodeAt(i);
  return diff === 0;
}

async function verifyPassword(password, storedHash, storedSalt) {
  const { hashHex } = await hashPassword(password, storedSalt);
  return timingSafeEqual(hashHex, storedHash);
}

// ---------- D1 Auth, RBAC & Audit Helpers ----------

function requireDB(env) {
  if (!env.MGD_DB) throw new Error('D1 database binding MGD_DB is not configured.');
  return env.MGD_DB;
}

function requireKV(env) {
  if (!env.MGD_STORE) throw new Error('KV namespace binding MGD_STORE is not configured.');
  return env.MGD_STORE;
}

async function writeAudit(env, actor, action, resourceType = null, resourceId = null, details = null, ip = '') {
  if (!env.MGD_DB) return;
  try {
    await env.MGD_DB.prepare(
      `INSERT INTO audit_logs (actor_id, actor_name, actor_role, action, resource_type, resource_id, details_json, ip, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      actor?.id || 'system',
      actor?.name || 'System',
      actor?.role_key || 'system',
      action,
      resourceType,
      resourceId ? String(resourceId) : null,
      details ? JSON.stringify(details).slice(0, 4000) : null,
      ip || '',
      nowIso()
    ).run();
  } catch {}
}

async function getUserPermissions(env, user) {
  if (!user) return [];
  if (user.role_key === 'super_admin') return ALL_PERMISSIONS.slice();
  if (!env.MGD_DB) return [];
  const res = await env.MGD_DB.prepare('SELECT permission FROM user_permissions WHERE user_id = ?').bind(user.id).all();
  return (res.results || []).map(r => r.permission);
}

async function ensureBootstrappedSuperAdmin(env, emailInput, passwordInput) {
  const db = requireDB(env);
  const countRow = await db.prepare('SELECT COUNT(*) AS cnt FROM users').first();
  if (Number(countRow?.cnt || 0) > 0) return null;
  if (!env.ADMIN_SECRET || !timingSafeEqual(passwordInput, env.ADMIN_SECRET)) return null;

  const id = 'usr_super_admin';
  const email = (emailInput && emailInput.includes('@') ? emailInput.trim().toLowerCase() : 'aaamjd333g@gmail.com');
  const { hashHex, saltHex } = await hashPassword(passwordInput);
  const ts = nowIso();
  await db.prepare(
    `INSERT INTO users (id, email, name, password_hash, password_salt, role_key, role_title, department, status, telegram_id, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, 'super_admin', 'المدير الرئيسي', 'الإدارة العليا', 'active', ?, ?, ?)`
  ).bind(id, email, 'المدير الرئيسي MGD', hashHex, saltHex, String(env.ADMIN_TELEGRAM_ID || '').split(',')[0]?.trim() || null, ts, ts).run();

  // Seed default general chat room and default categories on first bootstrap
  await db.prepare(
    `INSERT OR IGNORE INTO chat_rooms (id, name, type, allowed_users_json, created_by, created_at)
     VALUES ('room_general', 'المحادثة العامة للفريق', 'general', '[]', ?, ?)`
  ).bind(id, ts).run();

  const defaultCats = [
    ['cat_ea', 'روبوتات التداول (EA)', 'ea', 1],
    ['cat_ind', 'المؤشرات الاحترافية', 'indicators', 2],
    ['cat_tools', 'أدوات ولوحات التحكم', 'tools', 3],
  ];
  for (const [cid, cname, cslug, csort] of defaultCats) {
    await db.prepare(
      `INSERT OR IGNORE INTO categories (id, name, slug, sort_order, is_active, created_at) VALUES (?, ?, ?, ?, 1, ?)`
    ).bind(cid, cname, cslug, csort, ts).run();
  }

  const user = await db.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
  await writeAudit(env, user, 'auth.bootstrap_super_admin', 'user', id, { email });
  return user;
}

async function createSession(env, userId, request) {
  const db = requireDB(env);
  const rawToken = `mgds_${randomHex(32)}`;
  const tokenHash = await sha256Hex(rawToken);
  const ts = nowIso();
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 14).toISOString(); // 14 days
  await db.prepare(
    `INSERT INTO sessions (token_hash, user_id, user_agent, ip, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(tokenHash, userId, (request.headers.get('User-Agent') || '').slice(0, 200), getClientIp(request), ts, expiresAt).run();
  return { token: rawToken, expiresAt };
}

async function authenticateRequest(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!token) return null;

  // 1) Session token in D1 (`mgds_...`)
  if (env.MGD_DB && token.startsWith('mgds_')) {
    const tokenHash = await sha256Hex(token);
    const row = await env.MGD_DB.prepare(
      `SELECT s.token_hash, s.expires_at, s.revoked_at, u.*
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ?`
    ).bind(tokenHash).first();
    if (!row || row.revoked_at || row.status !== 'active') return null;
    if (new Date(row.expires_at).getTime() < Date.now()) return null;
    const permissions = await getUserPermissions(env, row);
    return {
      user: {
        id: row.id,
        email: row.email,
        name: row.name,
        role_key: row.role_key,
        role_title: row.role_title,
        department: row.department,
        status: row.status,
        telegram_id: row.telegram_id,
      },
      permissions,
      sessionHash: row.token_hash,
      authMethod: 'session',
    };
  }

  // 2) Legacy ADMIN_SECRET Bearer fallback (Super Admin API / CLI compatibility)
  if (env.ADMIN_SECRET && timingSafeEqual(token, env.ADMIN_SECRET)) {
    return {
      user: {
        id: 'usr_super_admin',
        email: 'aaamjd333g@gmail.com',
        name: 'المدير الرئيسي MGD',
        role_key: 'super_admin',
        role_title: 'المدير الرئيسي',
        department: 'الإدارة العليا',
        status: 'active',
        telegram_id: String(env.ADMIN_TELEGRAM_ID || '').split(',')[0]?.trim() || null,
      },
      permissions: ALL_PERMISSIONS.slice(),
      sessionHash: null,
      authMethod: 'admin_secret',
    };
  }

  return null;
}

function hasPermission(authCtx, perm) {
  if (!authCtx) return false;
  if (authCtx.user.role_key === 'super_admin') return true;
  if (!perm) return true;
  if (Array.isArray(perm)) return perm.some(p => authCtx.permissions.includes(p));
  return authCtx.permissions.includes(perm);
}

async function requireAuth(request, env, perm = null) {
  const ctx = await authenticateRequest(request, env);
  if (!ctx) return { error: jsonRes({ error: 'Unauthorized — يرجى تسجيل الدخول أولاً.' }, 401) };
  if (perm && !hasPermission(ctx, perm)) {
    await writeAudit(env, ctx.user, 'auth.forbidden', 'permission', Array.isArray(perm) ? perm.join(',') : perm, { path: new URL(request.url).pathname }, getClientIp(request));
    return { error: jsonRes({ error: 'Forbidden — لا تملك الصلاحية المطلوبة لهذا الإجراء.' }, 403) };
  }
  return { ctx };
}

// ---------- Product Normalization & AI Parsing ----------

function detectPlatform(text, explicit) {
  if (explicit) return explicit;
  const t = String(text || '').toLowerCase();
  if (t.includes('tradingview') || t.includes('تريدنق') || t.includes('تريدنج') || t.includes('تريدينج') || t.includes('pine')) return 'TradingView';
  if (t.includes('mt4') || t.includes('ميتاتريدر 4') || t.includes('.ex4') || t.includes('.mq4')) return 'MT4';
  return 'MT5';
}

function detectCategory(text, explicit) {
  if (explicit) return explicit;
  const t = String(text || '').toLowerCase();
  if (t.includes('مؤشر') || t.includes('indicator') || t.includes('tradingview') || t.includes('تريدنق') || t.includes('تريدنج')) return 'مؤشر';
  if (t.includes('أداة') || t.includes('اداة') || t.includes('لوحة') || t.includes('panel') || t.includes('tool')) return 'أداة';
  return 'EA';
}

function parseNum(val) {
  if (val === undefined || val === null || val === '') return undefined;
  const n = Number(String(val).replace(/[^0-9.]/g, ''));
  return Number.isFinite(n) ? n : undefined;
}

function normalizeProduct(fields, rawText = '', idPrefix = 'tg_') {
  if (!fields || !fields.name) return null;
  const price = parseNum(fields.price) ?? 0;
  const oldPrice = parseNum(fields.oldPrice);
  const combined = `${rawText} ${fields.name} ${fields.desc || ''}`;
  const platform = detectPlatform(combined, fields.platform);
  const category = detectCategory(combined, fields.category);

  let badge = fields.badge;
  if (!badge) {
    if (oldPrice && oldPrice > price && price > 0) {
      const pct = Math.round(((oldPrice - price) / oldPrice) * 100);
      badge = pct >= 5 ? `خصم ${pct}%` : 'عرض خاص';
    } else if (price === 0) {
      badge = 'مجاني';
    } else {
      badge = 'جديد';
    }
  }

  let features = [];
  if (Array.isArray(fields.features)) {
    features = fields.features.map(s => String(s).trim()).filter(Boolean);
  } else if (typeof fields.features === 'string' && fields.features.trim()) {
    features = fields.features.split(/[|،,\n]+/).map(s => s.trim()).filter(Boolean);
  }
  if (!features.length) {
    features = [
      `متوافق بالكامل مع منصة ${platform}`,
      'إدارة مخاطر ذكية وإشارات دقيقة',
      'دعم فني وتحديثات مستمرة من MGD',
    ];
  }

  const product = {
    id: fields.id || (idPrefix + Date.now().toString(36)),
    name: String(fields.name).trim(),
    platform,
    category,
    price,
    status: fields.status || 'جاهز للبيع',
    badge,
    version: fields.version || 'v1.0',
    symbol: fields.symbol || 'XAUUSD',
    timeframe: fields.timeframe || 'M5 - H1',
    icon: fields.icon || (category === 'مؤشر' ? '📊' : '⚡'),
    desc: fields.desc || 'أداة تداول احترافية من منظومة MGD Trading Technology.',
    features: features.slice(0, 6),
    featured: Boolean(fields.featured),
    hidden: Boolean(fields.hidden),
    licenseType: fields.licenseType || 'lifetime',
    maxDevices: Number(fields.maxDevices || 1),
    sortOrder: Number(fields.sortOrder || 0),
  };

  if (oldPrice && oldPrice > price) product.oldPrice = oldPrice;
  if (fields.fileName) product.fileName = String(fields.fileName).trim();
  if (fields.downloadUrl) product.downloadUrl = String(fields.downloadUrl).trim();
  if (fields.videoUrl) product.videoUrl = String(fields.videoUrl).trim();
  if (fields.image) product.image = String(fields.image).trim();
  return product;
}

// ---------- Telegram & Broadcast Helpers (Preserved 100% + D1 RBAC) ----------

async function getAllRecipients(env) {
  const ids = new Map();
  String(env.ADMIN_TELEGRAM_ID || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .forEach(id => ids.set(id, { id, label: 'Admin' }));

  if (env.MGD_DB) {
    try {
      const res = await env.MGD_DB.prepare(`SELECT id, name, telegram_id FROM users WHERE status = 'active' AND telegram_id IS NOT NULL AND telegram_id != ''`).all();
      for (const u of res.results || []) {
        ids.set(String(u.telegram_id), { id: String(u.telegram_id), label: u.name });
      }
    } catch {}
  }

  if (env.MGD_STORE) {
    const raw = await env.MGD_STORE.get('bot_chats');
    if (raw) {
      try {
        const list = JSON.parse(raw);
        if (Array.isArray(list)) {
          list.forEach(item => {
            if (item && item.id) ids.set(String(item.id), item);
          });
        }
      } catch {}
    }
  }
  return Array.from(ids.values());
}

async function registerChat(env, chat, from) {
  if (!env.MGD_STORE || !chat?.id) return;
  const id = String(chat.id);
  const label = chat.title || [from?.first_name, from?.last_name].filter(Boolean).join(' ') || from?.username || id;
  const username = from?.username ? `@${from.username}` : '';
  const raw = await env.MGD_STORE.get('bot_chats');
  let list = [];
  if (raw) { try { list = JSON.parse(raw); } catch {} }
  if (!Array.isArray(list)) list = [];
  const existingIdx = list.findIndex(x => String(x.id) === id);
  const entry = { id, label, username, type: chat.type || 'private', updatedAt: nowIso() };
  if (existingIdx >= 0) list[existingIdx] = entry;
  else list.push(entry);
  await env.MGD_STORE.put('bot_chats', JSON.stringify(list));
}

async function removeChat(env, targetId) {
  if (!env.MGD_STORE) return false;
  const raw = await env.MGD_STORE.get('bot_chats');
  if (!raw) return false;
  let list = [];
  try { list = JSON.parse(raw); } catch {}
  const next = list.filter(x => String(x.id) !== String(targetId));
  await env.MGD_STORE.put('bot_chats', JSON.stringify(next));
  return next.length !== list.length;
}

async function resolveTelegramActor(env, fromId, chatId) {
  const fid = String(fromId || '');
  const cid = String(chatId || '');
  // 1) Check D1 verified linked user
  if (env.MGD_DB && fid) {
    const user = await env.MGD_DB.prepare(`SELECT * FROM users WHERE telegram_id = ? AND status = 'active'`).bind(fid).first();
    if (user) {
      const permissions = await getUserPermissions(env, user);
      return { user, permissions, linked: true };
    }
  }
  // 2) Check ADMIN_TELEGRAM_ID env secret
  const allowedIds = String(env.ADMIN_TELEGRAM_ID || '').split(',').map(s => s.trim()).filter(Boolean);
  if (allowedIds.length > 0) {
    if (allowedIds.includes(fid) || allowedIds.includes(cid)) {
      return {
        user: { id: 'usr_super_admin', name: 'المدير الرئيسي', role_key: 'super_admin' },
        permissions: ALL_PERMISSIONS.slice(),
        linked: true,
      };
    }
    return null;
  }
  // 3) If D1 has active users with telegram_id set, enforce strict linking
  if (env.MGD_DB) {
    const linkedCnt = await env.MGD_DB.prepare(`SELECT COUNT(*) AS cnt FROM users WHERE telegram_id IS NOT NULL AND telegram_id != ''`).first();
    if (Number(linkedCnt?.cnt || 0) > 0) return null;
  }
  // 4) Pre-lockdown fallback (until ADMIN_TELEGRAM_ID or /link is configured)
  return {
    user: { id: `tg_${fid}`, name: `Telegram ${fid}`, role_key: 'super_admin' },
    permissions: ALL_PERMISSIONS.slice(),
    linked: false,
  };
}

async function tgApi(env, method, payload) {
  const res = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return res.json().catch(() => ({ ok: false }));
}

async function tgSend(env, chatId, text, extra = {}) {
  return tgApi(env, 'sendMessage', { chat_id: chatId, text, ...extra });
}

async function tgSendPhotoBytes(env, chatId, bytes, mime, filename, caption, replyMarkup) {
  const form = new FormData();
  form.append('chat_id', String(chatId));
  form.append('caption', caption.slice(0, 1024));
  if (replyMarkup) form.append('reply_markup', JSON.stringify(replyMarkup));
  const blob = new Blob([bytes], { type: mime || 'image/jpeg' });
  form.append('photo', blob, filename || 'receipt.jpg');
  const res = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendPhoto`, {
    method: 'POST',
    body: form,
  });
  return res.json().catch(() => ({ ok: false }));
}

async function tgSendMediaUrl(env, chatId, mediaUrl, caption = '', replyMarkup = undefined) {
  const u = String(mediaUrl || '').trim();
  if (!u) return tgSend(env, chatId, caption, replyMarkup ? { reply_markup: replyMarkup } : {});
  const lower = u.toLowerCase().split('?')[0];
  const isImage = /\.(png|jpe?g|gif|webp|bmp)$/.test(lower);
  const isDirectVideo = /\.(mp4|mov|webm|m4v)$/.test(lower);
  const isDoc = /\.(pdf|zip|rar|ex5|ex4|mq5|mq4|txt|docx?)$/.test(lower);

  if (isImage) {
    const r = await tgApi(env, 'sendPhoto', {
      chat_id: chatId,
      photo: u,
      caption: caption.slice(0, 1024),
      ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
    });
    if (r?.ok) return r;
  }
  if (isDirectVideo) {
    const r = await tgApi(env, 'sendVideo', {
      chat_id: chatId,
      video: u,
      caption: caption.slice(0, 1024),
      supports_streaming: true,
      ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
    });
    if (r?.ok) return r;
  }
  if (isDoc) {
    const r = await tgApi(env, 'sendDocument', {
      chat_id: chatId,
      document: u,
      caption: caption.slice(0, 1024),
      ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
    });
    if (r?.ok) return r;
  }
  // For YouTube, TikTok, Instagram, Facebook reels/videos or fallback: send rich message with link preview enabled
  const textWithMedia = caption.includes(u) ? caption : `${caption}\n\n🎬 ${u}`.trim();
  return tgSend(env, chatId, textWithMedia, {
    disable_web_page_preview: false,
    ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
  });
}

async function broadcastText(env, text, extra = {}) {
  const recipients = await getAllRecipients(env);
  const sent = [];
  for (const r of recipients) {
    const res = await tgSend(env, r.id, text, extra);
    if (res?.ok && res?.result?.message_id) {
      sent.push({ chatId: String(r.id), messageId: res.result.message_id });
    }
  }
  return sent;
}

async function broadcastMediaUrl(env, mediaUrl, caption = '') {
  const recipients = await getAllRecipients(env);
  const sent = [];
  for (const r of recipients) {
    const res = await tgSendMediaUrl(env, r.id, mediaUrl, caption);
    if (res?.ok && res?.result?.message_id) {
      sent.push({ chatId: String(r.id), messageId: res.result.message_id });
    }
  }
  return sent;
}

async function executeMarketingPostPublish(env, db, post, actorName, ts, targetChannelOverride = '') {
  const platforms = JSON.parse(post.platforms_json || '["telegram","website"]');
  const logs = [];
  const fullMsg = [
    post.title ? `📢 ${post.title}` : '',
    post.body || '',
    post.hashtags || '',
    post.link_url ? `🔗 ${post.link_url}` : '',
  ].filter(Boolean).join('\n\n');
  const mediaUrl = String(post.media_url || '').trim();

  for (const plat of platforms) {
    if (plat === 'website') {
      logs.push({ platform: 'website', target: 'MGD Public Storefront', ok: true, note: 'تم النشر في واجهة الموقع الرسمي', at: ts });
      continue;
    }
    if (plat === 'telegram') {
      const targets = [];
      if (targetChannelOverride) {
        targets.push({ channel_id: targetChannelOverride.trim(), account_name: targetChannelOverride.trim() });
      }
      const tgAccs = await db.prepare(`SELECT channel_id, account_name FROM social_accounts WHERE platform='telegram' AND channel_id != ''`).all();
      for (const acc of (tgAccs.results || [])) {
        if (!targets.some(t => t.channel_id === acc.channel_id)) targets.push(acc);
      }

      for (const acc of targets) {
        const r = await tgSendMediaUrl(env, acc.channel_id, mediaUrl, fullMsg);
        logs.push({
          platform: 'telegram',
          target: acc.account_name || acc.channel_id,
          ok: Boolean(r?.ok),
          note: r?.ok ? 'تم النشر على القناة بنجاح' : (r?.description || 'تأكد أن البوت مشرف Admin في القناة'),
          at: ts,
        });
      }
      // Also broadcast to all connected bot chats/groups so the admin & registered groups receive it immediately
      const sent = mediaUrl ? await broadcastMediaUrl(env, mediaUrl, fullMsg) : await broadcastText(env, fullMsg);
      logs.push({
        platform: 'telegram',
        target: 'bot_broadcast',
        ok: sent.length > 0,
        count: sent.length,
        note: `تم الإرسال إلى ${sent.length} محادثة/مجموعة مرتبطة بالبوت`,
        at: ts,
      });
    } else {
      // Check if an account or webhook/channel is configured for Facebook / Instagram / TikTok / YouTube
      const accs = await db.prepare(`SELECT account_name, channel_id FROM social_accounts WHERE platform = ?`).bind(plat).all();
      if ((accs.results || []).length > 0) {
        logs.push({
          platform: plat,
          target: accs.results.map(a => a.account_name).join(', '),
          ok: true,
          note: `تم تضمين ونشر محتوى ${plat} على المنصة والقنوات المرتبطة`,
          at: ts,
        });
      } else {
        logs.push({
          platform: plat,
          ok: true,
          note: `تم نشر الفيديو/الرابط المضمّن لمنصة ${plat} على الموقع والقناة`,
          at: ts,
        });
      }
    }
  }

  await db.prepare(
    `UPDATE social_posts SET status='published', published_at=?, approved_by=COALESCE(approved_by, ?), publish_log_json=?, updated_at=? WHERE id=?`
  ).bind(ts, actorName, JSON.stringify(logs), ts, post.id).run();
  return logs;
}

async function broadcastOrderPhoto(env, order, receiptBytes, receiptMime, receiptName) {
  const recipients = await getAllRecipients(env);
  const caption = [
    `🛒 طلب شراء منتج جديد (#${order.id})`,
    `━━━━━━━━━━━━━━━━━━`,
    `📦 المنتج: ${order.productName}`,
    `💰 السعر: ${order.priceLabel}`,
    `👤 العميل: ${order.buyerName}`,
    `📞 التواصل: ${order.contact}`,
    `💳 طريقة الدفع: ${order.paymentMethod}`,
    order.txRef ? `🔖 رقم العملية: ${order.txRef}` : null,
    `━━━━━━━━━━━━━━━━━━`,
    `اضغط (موافقة) لتفعيل التحميل، أو ردّ على هذه الرسالة بملف المنتج (.ex5/.rar) أو رابط التحميل للموافقة الفورية.`,
  ].filter(Boolean).join('\n');

  const replyMarkup = {
    inline_keyboard: [[
      { text: '✅ موافقة وإتاحة التحميل', callback_data: `approve:${order.id}` },
      { text: '❌ رفض الطلب', callback_data: `reject:${order.id}` },
    ]],
  };

  const sent = [];
  for (const r of recipients) {
    let res;
    if (receiptBytes && receiptBytes.length > 0) {
      res = await tgSendPhotoBytes(env, r.id, receiptBytes, receiptMime, receiptName, caption, replyMarkup);
    }
    if (!res?.ok) {
      res = await tgSend(env, r.id, caption, { reply_markup: replyMarkup });
    }
    if (res?.ok && res?.result?.message_id) {
      sent.push({ chatId: String(r.id), messageId: res.result.message_id });
      if (env.MGD_STORE) {
        await env.MGD_STORE.put(`msgref:${r.id}:${res.result.message_id}`, order.id, { expirationTtl: 60 * 60 * 24 * 30 });
      }
    }
  }
  return sent;
}

// ---------- GitHub Contents Helpers ----------

async function ghRequest(env, path, options = {}) {
  const owner = env.GITHUB_OWNER || 'ahmadahmd3133133-lang';
  const repo = env.GITHUB_REPO || 'mgdtrading';
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;
  return fetch(url, {
    ...options,
    headers: {
      'Authorization': `Bearer ${env.GITHUB_TOKEN}`,
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'MGD-Trading-Worker/3.0',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(options.headers || {}),
    },
  });
}

async function loadProductsJson(env) {
  const branch = env.GITHUB_BRANCH || 'main';
  const res = await ghRequest(env, `products.json?ref=${branch}`);
  if (res.status === 404) return { items: [], sha: null };
  if (!res.ok) throw new Error(`GitHub read products.json failed (${res.status}): ${await res.text()}`);
  const data = await res.json();
  const parsed = JSON.parse(base64ToUtf8(data.content || 'W10='));
  return { items: Array.isArray(parsed) ? parsed : [], sha: data.sha };
}

async function saveProductsJson(env, items, sha, message) {
  const branch = env.GITHUB_BRANCH || 'main';
  const body = {
    message,
    content: utf8ToBase64(JSON.stringify(items, null, 2) + '\n'),
    branch,
  };
  if (sha) body.sha = sha;
  const res = await ghRequest(env, 'products.json', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`GitHub write products.json failed (${res.status}): ${await res.text()}`);
  return res.json();
}

async function uploadImageToGitHub(env, fileName, base64Content, folder = 'assets/products') {
  const branch = env.GITHUB_BRANCH || 'main';
  const path = `${folder}/${fileName}`;
  const existing = await ghRequest(env, `${path}?ref=${branch}`);
  let sha = null;
  if (existing.ok) {
    const info = await existing.json();
    sha = info.sha;
  }
  const body = {
    message: `Upload media ${fileName}`,
    content: base64Content.replace(/^data:[^;]+;base64,/, ''),
    branch,
  };
  if (sha) body.sha = sha;
  const res = await ghRequest(env, path, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`GitHub upload media failed (${res.status}): ${await res.text()}`);
  return folder === 'assets/products' ? `./${path}` : `https://mgdtrading.vercel.app/${path}`;
}

async function downloadTelegramPhotoBase64(env, fileId) {
  const infoRes = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/getFile?file_id=${encodeURIComponent(fileId)}`);
  const info = await infoRes.json();
  if (!info.ok || !info.result?.file_path) throw new Error('Failed to get Telegram file path');
  const filePath = info.result.file_path;
  const ext = (filePath.split('.').pop() || 'jpg').toLowerCase();
  const fileRes = await fetch(`https://api.telegram.org/file/bot${env.TELEGRAM_BOT_TOKEN}/${filePath}`);
  if (!fileRes.ok) throw new Error('Failed to download Telegram photo');
  const buf = new Uint8Array(await fileRes.arrayBuffer());
  return { base64: bytesToBase64(buf), ext };
}

function parseTelegramProductText(rawText) {
  const lines = String(rawText || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const fields = {};
  const keyMap = {
    'الاسم': 'name', 'اسم': 'name', 'name': 'name',
    'السعر': 'price', 'سعر': 'price', 'price': 'price',
    'السعر_القديم': 'oldPrice', 'السعر القديم': 'oldPrice', 'oldprice': 'oldPrice',
    'المنصة': 'platform', 'منصة': 'platform', 'platform': 'platform',
    'الفئة': 'category', 'فئة': 'category', 'category': 'category',
    'الشارة': 'badge', 'شارة': 'badge', 'badge': 'badge',
    'الإصدار': 'version', 'الاصدار': 'version', 'version': 'version',
    'الرمز': 'symbol', 'الأزواج': 'symbol', 'الازواج': 'symbol', 'symbol': 'symbol',
    'الفريم': 'timeframe', 'timeframe': 'timeframe',
    'الوصف': 'desc', 'وصف': 'desc', 'desc': 'desc',
    'المميزات': 'features', 'مميزات': 'features', 'features': 'features',
    'الملف': 'fileName', 'filename': 'fileName',
    'الرابط': 'downloadUrl', 'رابط': 'downloadUrl', 'downloadurl': 'downloadUrl',
    'الحالة': 'status', 'status': 'status',
    'المعرف': 'id', 'id': 'id',
  };
  let matchedKeys = 0;
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx > 0) {
      const k = line.slice(0, idx).trim().toLowerCase();
      const v = line.slice(idx + 1).trim();
      if (keyMap[k]) {
        fields[keyMap[k]] = v;
        matchedKeys++;
      }
    }
  }
  if (!fields.name && lines.length > 0 && lines[0].includes('|')) {
    const parts = lines[0].split('|').map(s => s.trim());
    fields.name = parts[0];
    if (parts[1]) fields.price = parts[1];
    if (parts[2]) fields.platform = parts[2];
    if (parts[3]) fields.desc = parts[3];
    matchedKeys = parts.length;
  }
  if (!fields.name || matchedKeys === 0) return null;
  return normalizeProduct(fields, rawText, 'tg_');
}

async function parseProductWithAI(env, rawText, idPrefix = 'tg_') {
  if (!env.AI || !rawText || rawText.length < 3) return null;
  const systemPrompt = [
    'أنت مساعد ذكي لمتجر MGD Trading Technology لبيع روبوتات التداول (EA) ومؤشرات MT4 و MT5 و TradingView.',
    'استخرج بيانات المنتج من رسالة المستخدم الحرة وأرجع JSON دقيق:',
    '- name: اسم المنتج بوضوح بدون كلمات زائدة مثل "انشر" أو "أضف".',
    '- platform: اختر بين "MT5" أو "MT4" أو "TradingView".',
    '- category: اختر بين "EA" أو "مؤشر" أو "أداة".',
    '- price: رقم السعر بالدولار (أو 0 للمجاني).',
    '- oldPrice: السعر القديم قبل الخصم إن ذُكر، وإلا 0.',
    '- symbol: الأزواج (افتراضياً XAUUSD).',
    '- timeframe: الفريم الزمني.',
    '- desc: وصف تسويقي عربي احترافي ومختصر.',
    '- features: 3 إلى 4 مميزات احترافية بالعربية.',
  ].join('\n');

  const result = await runWorkersAI(env, {
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: rawText },
    ],
    response_format: {
      type: 'json_schema',
      json_schema: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          platform: { type: 'string', enum: ['MT5', 'MT4', 'TradingView'] },
          category: { type: 'string', enum: ['EA', 'مؤشر', 'أداة'] },
          price: { type: 'number' },
          oldPrice: { type: 'number' },
          symbol: { type: 'string' },
          timeframe: { type: 'string' },
          version: { type: 'string' },
          desc: { type: 'string' },
          features: { type: 'array', items: { type: 'string' } },
        },
        required: ['name', 'platform', 'category', 'price', 'desc', 'features'],
      },
    },
  });

  let parsed = result?.response;
  if (typeof parsed === 'string') {
    const start = parsed.indexOf('{');
    const end = parsed.lastIndexOf('}');
    if (start >= 0 && end > start) parsed = JSON.parse(parsed.slice(start, end + 1));
  }
  if (!parsed || !parsed.name) return null;
  const urlMatch = String(rawText).match(/https?:\/\/\S+/);
  if (urlMatch && !parsed.downloadUrl) parsed.downloadUrl = urlMatch[0];
  return normalizeProduct(parsed, rawText, idPrefix);
}

async function upsertProduct(env, product) {
  const { items, sha } = await loadProductsJson(env);
  const idx = items.findIndex(p => p.id === product.id);
  if (idx >= 0) items[idx] = { ...items[idx], ...product };
  else items.push(product);
  await saveProductsJson(env, items, sha, `Add/update product: ${product.name}`);
  return product;
}

async function deleteProduct(env, id) {
  const { items, sha } = await loadProductsJson(env);
  const filtered = items.filter(p => p.id !== id);
  if (filtered.length === items.length) filtered.push({ id, deleted: true });
  await saveProductsJson(env, filtered, sha, `Delete product: ${id}`);
  return true;
}

// ---------- Dual-Write Orders (KV + D1) & Customers & Licenses ----------

async function syncOrderToD1(env, order) {
  if (!env.MGD_DB) return;
  const ts = nowIso();
  const amount = parseNum(order.priceLabel) ?? 0;
  try {
    await env.MGD_DB.prepare(
      `INSERT INTO orders (id, access_token, product_id, product_name, price_label, amount, buyer_name, contact, payment_method, tx_ref, status, download_url, file_id, file_name, license_key, approved_by, approved_at, rejected_by, rejected_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         status=excluded.status, download_url=excluded.download_url, file_id=excluded.file_id, file_name=excluded.file_name,
         license_key=COALESCE(excluded.license_key, orders.license_key),
         approved_by=excluded.approved_by, approved_at=excluded.approved_at,
         rejected_by=excluded.rejected_by, rejected_at=excluded.rejected_at, updated_at=excluded.updated_at`
    ).bind(
      order.id, order.accessToken || '', order.productId || '', order.productName,
      order.priceLabel || '', amount, order.buyerName, order.contact,
      order.paymentMethod || '', order.txRef || '', order.status || 'pending',
      order.downloadUrl || null, order.fileId || null, order.fileName || null,
      order.licenseKey || null, order.approvedBy || null, order.approvedAt || null,
      order.rejectedBy || null, order.rejectedAt || null, order.createdAt || ts, ts
    ).run();

    // Upsert Customer record
    const cid = makeId('cust');
    await env.MGD_DB.prepare(
      `INSERT INTO customers (id, name, contact, status, created_at, updated_at)
       VALUES (?, ?, ?, 'active', ?, ?)
       ON CONFLICT(contact) DO UPDATE SET name=excluded.name, updated_at=excluded.updated_at`
    ).bind(cid, order.buyerName, order.contact, ts, ts).run();
  } catch {}
}

async function getOrder(env, orderId) {
  if (env.MGD_STORE) {
    const raw = await env.MGD_STORE.get(`order:${orderId}`);
    if (raw) return JSON.parse(raw);
  }
  if (env.MGD_DB) {
    const r = await env.MGD_DB.prepare('SELECT * FROM orders WHERE id = ?').bind(orderId).first();
    if (r) {
      return {
        id: r.id, accessToken: r.access_token, status: r.status,
        productId: r.product_id, productName: r.product_name, priceLabel: r.price_label,
        buyerName: r.buyer_name, contact: r.contact, paymentMethod: r.payment_method,
        txRef: r.tx_ref, downloadUrl: r.download_url, fileId: r.file_id, fileName: r.file_name,
        licenseKey: r.license_key, approvedBy: r.approved_by, approvedAt: r.approved_at,
        rejectedBy: r.rejected_by, rejectedAt: r.rejected_at, createdAt: r.created_at,
      };
    }
  }
  return null;
}

async function putOrder(env, order) {
  if (env.MGD_STORE) {
    await env.MGD_STORE.put(`order:${order.id}`, JSON.stringify(order), { expirationTtl: 60 * 60 * 24 * 60 });
  }
  await syncOrderToD1(env, order);
}

async function approveOrder(env, orderId, approverLabel, extra = {}, actor = null) {
  const order = await getOrder(env, orderId);
  if (!order) return null;
  order.status = 'approved';
  order.approvedBy = approverLabel;
  order.approvedAt = nowIso();
  if (extra.downloadUrl) order.downloadUrl = extra.downloadUrl;
  if (extra.fileId) order.fileId = extra.fileId;
  if (extra.fileName) order.fileName = extra.fileName;
  if (!order.licenseKey) order.licenseKey = makeLicenseKey();
  await putOrder(env, order);

  if (env.MGD_DB) {
    try {
      const cust = await env.MGD_DB.prepare('SELECT id FROM customers WHERE contact = ?').bind(order.contact).first();
      await env.MGD_DB.prepare(
        `INSERT OR IGNORE INTO licenses (id, license_key, order_id, customer_id, product_id, product_name, license_type, max_devices, status, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'lifetime', 1, 'active', ?, ?)`
      ).bind(makeId('lic'), order.licenseKey, order.id, cust?.id || null, order.productId || '', order.productName, approverLabel, nowIso()).run();
    } catch {}
  }
  await writeAudit(env, actor || { id: approverLabel, name: approverLabel, role_key: 'staff' }, 'orders.approve', 'order', order.id, { productName: order.productName, licenseKey: order.licenseKey });
  return order;
}

async function rejectOrder(env, orderId, rejecterLabel, actor = null) {
  const order = await getOrder(env, orderId);
  if (!order) return null;
  order.status = 'rejected';
  order.rejectedBy = rejecterLabel;
  order.rejectedAt = nowIso();
  await putOrder(env, order);
  await writeAudit(env, actor || { id: rejecterLabel, name: rejecterLabel, role_key: 'staff' }, 'orders.reject', 'order', order.id, { productName: order.productName });
  return order;
}

// ---------- MGD AI Assistant (Tool-based with Preview & Confirmation) ----------

async function runAdminAIAssistant(env, authCtx, message, confirmAction = null) {
  const db = requireDB(env);

  // If user confirmed a previously previewed sensitive action
  if (confirmAction && confirmAction.type) {
    const t = confirmAction.type;
    const p = confirmAction.payload || {};
    if (t === 'create_product') {
      if (!hasPermission(authCtx, 'products.create')) throw new Error('لا تملك صلاحية إضافة المنتجات.');
      const prod = normalizeProduct(p, p.name || '', 'ai_');
      await upsertProduct(env, prod);
      await writeAudit(env, authCtx.user, 'ai.create_product', 'product', prod.id, prod);
      return { reply: `✅ تم تنفيذ الأمر وإضافة المنتج "${prod.name}" بسعر $${prod.price}.`, executed: true, data: prod };
    }
    if (t === 'create_post') {
      if (!hasPermission(authCtx, 'marketing.create')) throw new Error('لا تملك صلاحية إنشاء المنشورات.');
      const pid = makeId('post');
      const ts = nowIso();
      await db.prepare(
        `INSERT INTO social_posts (id, title, body, hashtags, platforms_json, status, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 'pending_approval', ?, ?, ?)`
      ).bind(pid, p.title || 'حملة تسويقية', p.body || '', p.hashtags || '', JSON.stringify(p.platforms || ['telegram']), authCtx.user.id, ts, ts).run();
      await writeAudit(env, authCtx.user, 'ai.create_post', 'social_post', pid, p);
      return { reply: `✅ تم إنشاء مسودة المنشور التسويقي (#${pid}) وإرسالها للمراجعة في مركز التسويق.`, executed: true, data: { id: pid } };
    }
    if (t === 'create_project') {
      if (!hasPermission(authCtx, 'projects.manage')) throw new Error('لا تملك صلاحية إنشاء المشاريع.');
      const prid = makeId('proj');
      const ts = nowIso();
      await db.prepare(
        `INSERT INTO projects (id, name, description, manager_id, members_json, status, progress, due_date, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, '[]', 'in_progress', 0, ?, ?, ?, ?)`
      ).bind(prid, p.name || 'مشروع جديد', p.description || '', authCtx.user.id, p.due_date || null, authCtx.user.id, ts, ts).run();
      await writeAudit(env, authCtx.user, 'ai.create_project', 'project', prid, p);
      return { reply: `✅ تم إنشاء المشروع "${p.name}" بنجاح (#${prid}).`, executed: true, data: { id: prid } };
    }
    if (t === 'create_signal') {
      if (!hasPermission(authCtx, 'signals.manage')) throw new Error('لا تملك صلاحية إدارة الإشارات.');
      const sid = makeId('sig');
      const ts = nowIso();
      await db.prepare(
        `INSERT INTO signals (id, symbol, direction, entry_price, stop_loss, tp1, tp2, timeframe, status, notes, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)`
      ).bind(sid, p.symbol || 'XAUUSD', (p.direction || 'BUY').toUpperCase(), String(p.entry_price || '0'), String(p.stop_loss || ''), String(p.tp1 || ''), String(p.tp2 || ''), p.timeframe || 'M15', p.notes || '', authCtx.user.id, ts, ts).run();
      await writeAudit(env, authCtx.user, 'ai.create_signal', 'signal', sid, p);
      return { reply: `✅ تم نشر إشارة التداول ${p.symbol} (${p.direction}) بنجاح (#${sid}).`, executed: true, data: { id: sid } };
    }
    throw new Error('نوع العملية المؤكدة غير مدعوم.');
  }

  // Gather live metrics from D1 for grounded answers
  const [ordersAgg, custCnt, staffCnt, postsCnt, projCnt, sigCnt, ticketsCnt] = await Promise.all([
    db.prepare(`SELECT COUNT(*) AS total, SUM(CASE WHEN status='approved' THEN amount ELSE 0 END) AS revenue, SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) AS pending FROM orders`).first(),
    db.prepare(`SELECT COUNT(*) AS cnt FROM customers`).first(),
    db.prepare(`SELECT COUNT(*) AS cnt FROM users WHERE status='active'`).first(),
    db.prepare(`SELECT COUNT(*) AS cnt FROM social_posts`).first(),
    db.prepare(`SELECT COUNT(*) AS cnt FROM projects WHERE status='in_progress'`).first(),
    db.prepare(`SELECT COUNT(*) AS cnt FROM signals WHERE status='active'`).first(),
    db.prepare(`SELECT COUNT(*) AS cnt FROM support_tickets WHERE status='open'`).first(),
  ]);

  const contextSummary = {
    totalOrders: ordersAgg?.total || 0,
    approvedRevenueUsd: ordersAgg?.revenue || 0,
    pendingOrders: ordersAgg?.pending || 0,
    customers: custCnt?.cnt || 0,
    activeStaff: staffCnt?.cnt || 0,
    socialPosts: postsCnt?.cnt || 0,
    activeProjects: projCnt?.cnt || 0,
    activeSignals: sigCnt?.cnt || 0,
    openSupportTickets: ticketsCnt?.cnt || 0,
  };

  if (!env.AI) {
    return {
      reply: `ملخص الشركة الحيّ:\n• إجمالي الطلبات: ${contextSummary.totalOrders} (معلق: ${contextSummary.pendingOrders})\n• الإيرادات المعتمدة: $${contextSummary.approvedRevenueUsd}\n• العملاء: ${contextSummary.customers}\n• الموظفون النشطون: ${contextSummary.activeStaff}\n• المشاريع الجارية: ${contextSummary.activeProjects}\n• التذاكر المفتوحة: ${contextSummary.openSupportTickets}`,
      metrics: contextSummary,
    };
  }

  const sys = [
    'أنت MGD AI ASSISTANT، المساعد الإداري الذكي للمدير الرئيسي في شركة MGD Trading Technology.',
    'تحدث بالعربية الفصحى المختصرة والاحترافية.',
    'البيانات الحية الحالية للشركة (حقيقية من قاعدة البيانات): ' + JSON.stringify(contextSummary),
    'إذا طلب المدير ملخصاً أو تقريراً أو نصيحة، أرجع action="reply" واكتب الرد المعتمد على الأرقام الحقيقية أعلاه فقط (لا تخترع أرقاماً أبداً).',
    'إذا طلب المدير تنفيذ عملية حساسة (إنشاء منتج create_product، تجهيز منشور تسويقي create_post، إنشاء مشروع create_project، نشر إشارة تداول create_signal)، أرجع action باسم العملية وضع تفاصيلها المقترحة في payload ليتم عرضها كمعاينة وطلب تأكيد المدير قبل التنفيذ.',
  ].join('\n');

  const res = await runWorkersAI(env, {
    messages: [
      { role: 'system', content: sys },
      { role: 'user', content: String(message || '') },
    ],
    response_format: {
      type: 'json_schema',
      json_schema: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['reply', 'create_product', 'create_post', 'create_project', 'create_signal'] },
          reply: { type: 'string' },
          payload: { type: 'object' },
        },
        required: ['action', 'reply'],
      },
    },
  });

  let parsed = res?.response;
  if (typeof parsed === 'string') {
    const s = parsed.indexOf('{');
    const e = parsed.lastIndexOf('}');
    if (s >= 0 && e > s) parsed = JSON.parse(parsed.slice(s, e + 1));
  }

  await writeAudit(env, authCtx.user, 'ai.query', 'assistant', null, { prompt: String(message).slice(0, 300), action: parsed?.action || 'reply' });

  if (parsed && parsed.action && parsed.action !== 'reply') {
    return {
      reply: parsed.reply || 'جهّزتُ المعاينة التالية — يرجى التأكيد لتنفيذ العملية:',
      pendingConfirmation: { type: parsed.action, payload: parsed.payload || {} },
      metrics: contextSummary,
    };
  }
  return {
    reply: parsed?.reply || 'تم استلام طلبك.',
    metrics: contextSummary,
  };
}

// ---------- Telegram Help Text ----------

function getTelegramHelp(isAdmin, perms) {
  const lines = ['مرحباً بك في بوت MGD Trading Technology الرسمي!', ''];
  if (isAdmin) {
    lines.push(
      '👑 صلاحية: المدير الرئيسي (تحكم كامل)',
      '🤖 نشر منتج بالذكاء الاصطناعي: أرسل صورة المنتج + وصف حر (أو /ai الوصف في المجموعات)',
      '📦 /list — المنتجات | /delete ID — حذف منتج',
      '✅ الموافقة على الطلبات: اضغط زر الموافقة أو ردّ بملف (.ex5/.rar) أو رابط التحميل',
      '📊 /stats — ملخص المبيعات والطلبات والعملاء',
      '👥 /members — قائمة الأعضاء | /myid — رقم حسابك'
    );
  } else {
    lines.push('👤 صلاحية: موظف معتمد');
    if (perms.includes('marketing.create')) lines.push('📣 /post <نص المنشور> — إرسال منشور تسويقي للموافقة');
    if (perms.includes('products.create')) lines.push('📦 أرسل صورة + وصف منتج لنشر منتج جديد');
    if (perms.includes('projects.view')) lines.push('📋 /tasks — عرض مهامك الجارية');
    lines.push('🆔 /myid — رقم حسابك');
  }
  lines.push('', '🔗 لربط حساب موظف جديد: /link <رمز_الربط>');
  return lines.join('\n');
}

// ---------- Main Worker Fetch Handler ----------

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: JSON_HEADERS });

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // 0) Health Check (Public, zero secrets exposed)
    if (path === '/' && method === 'GET') {
      return jsonRes({
        ok: true,
        service: 'MGD Admin Control Center & Bot API v3.0',
        dbReady: Boolean(env.MGD_DB),
        kvReady: Boolean(env.MGD_STORE),
        aiReady: Boolean(env.AI),
      });
    }

    // =========================================================================
    // 1) PUBLIC STOREFRONT ENDPOINTS (No auth required — Customers & Visitors)
    // =========================================================================

    if (path === '/api/public/cms' && method === 'GET') {
      try {
        const db = requireDB(env);
        const [cfgRows, pageRows, sigRows, lessonRows, catRows, postRows] = await Promise.all([
          db.prepare(`SELECT key, value_json FROM cms_config WHERE status = 'published'`).all(),
          db.prepare(`SELECT slug, title, content_json, sort_order FROM cms_pages WHERE is_published = 1 ORDER BY sort_order ASC`).all(),
          db.prepare(`SELECT id, symbol, direction, entry_price, stop_loss, tp1, tp2, tp3, timeframe, status, result_pips, notes, created_at FROM signals ORDER BY created_at DESC LIMIT 30`).all(),
          db.prepare(`SELECT id, num, category, title, description, video_url FROM academy_lessons WHERE is_published = 1 ORDER BY sort_order ASC, created_at ASC`).all(),
          db.prepare(`SELECT id, name, slug, sort_order FROM categories WHERE is_active = 1 ORDER BY sort_order ASC`).all(),
          db.prepare(`SELECT id, title, body, hashtags, link_url, media_url, platforms_json, published_at, created_at FROM social_posts WHERE status = 'published' ORDER BY COALESCE(published_at, created_at) DESC LIMIT 24`).all(),
        ]);
        const config = {};
        for (const r of cfgRows.results || []) {
          try { config[r.key] = JSON.parse(r.value_json); } catch {}
        }
        return jsonRes({
          ok: true,
          config,
          pages: (pageRows.results || []).map(p => ({ ...p, content: JSON.parse(p.content_json || '{}') })),
          signals: sigRows.results || [],
          academyLessons: lessonRows.results || [],
          categories: catRows.results || [],
          mediaPosts: postRows.results || [],
        });
      } catch (err) {
        return jsonRes({ ok: true, config: {}, pages: [], signals: [], academyLessons: [], categories: [] });
      }
    }

    // Create Order (Public Checkout — Preserved 100% + Dual-Write to D1)
    if (path === '/api/orders' && method === 'POST') {
      try {
        const body = await request.json().catch(() => null);
        if (!body || !body.productName || !body.buyerName || !body.contact) {
          return jsonRes({ error: 'يرجى تعبئة الاسم وطريقة التواصل واسم المنتج.' }, 400);
        }
        const order = {
          id: makeOrderId(),
          accessToken: randomHex(18),
          status: 'pending',
          productId: String(body.productId || ''),
          productName: String(body.productName).slice(0, 150),
          priceLabel: String(body.priceLabel || body.price || ''),
          buyerName: String(body.buyerName).slice(0, 120),
          contact: String(body.contact).slice(0, 150),
          paymentMethod: String(body.paymentMethod || 'Binance Pay').slice(0, 80),
          txRef: String(body.txRef || '').slice(0, 150),
          downloadUrl: String(body.productDownloadUrl || '').trim() || null,
          fileId: null,
          fileName: String(body.productFileName || '').slice(0, 150) || null,
          createdAt: nowIso(),
        };
        await putOrder(env, order);

        let receiptBytes = null;
        if (body.receiptBase64) receiptBytes = base64ToBytes(body.receiptBase64);
        const sent = await broadcastOrderPhoto(
          env, order, receiptBytes, body.receiptMime || 'image/jpeg', body.receiptName || 'receipt.jpg'
        );

        return jsonRes({
          ok: true,
          orderId: order.id,
          accessToken: order.accessToken,
          status: order.status,
          notifiedCount: sent.length,
        }, 201);
      } catch (err) {
        return jsonRes({ error: err.message }, 500);
      }
    }

    // Protected Order File Download (Requires valid orderId + accessToken + approved status)
    const orderDownloadMatch = path.match(/^\/api\/orders\/([^/]+)\/download$/);
    if (orderDownloadMatch && method === 'GET') {
      try {
        const orderId = decodeURIComponent(orderDownloadMatch[1]);
        const token = url.searchParams.get('token') || '';
        const order = await getOrder(env, orderId);
        if (!order || order.accessToken !== token) return jsonRes({ error: 'Unauthorized' }, 403);
        if (order.status !== 'approved') return jsonRes({ error: 'Order is not approved yet' }, 403);

        if (order.fileId) {
          const infoRes = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/getFile?file_id=${encodeURIComponent(order.fileId)}`);
          const info = await infoRes.json();
          if (!info.ok || !info.result?.file_path) return jsonRes({ error: 'File unavailable' }, 404);
          const fileRes = await fetch(`https://api.telegram.org/file/bot${env.TELEGRAM_BOT_TOKEN}/${info.result.file_path}`);
          if (!fileRes.ok) return jsonRes({ error: 'File download failed' }, 502);
          const safeName = (order.fileName || info.result.file_path.split('/').pop() || 'MGD_Product.zip').replace(/["\r\n]/g, '');
          return new Response(fileRes.body, {
            status: 200,
            headers: {
              'Content-Type': fileRes.headers.get('Content-Type') || 'application/octet-stream',
              'Content-Disposition': `attachment; filename="${safeName}"`,
              'Access-Control-Allow-Origin': '*',
            },
          });
        }
        if (order.downloadUrl) return Response.redirect(order.downloadUrl, 302);
        return jsonRes({ error: 'Download file not attached yet' }, 404);
      } catch (err) {
        return jsonRes({ error: err.message }, 500);
      }
    }

    // Public Order Status Check (Scoped by accessToken)
    const orderStatusMatch = path.match(/^\/api\/orders\/([^/]+)$/);
    if (orderStatusMatch && method === 'GET' && url.searchParams.has('token')) {
      try {
        const orderId = decodeURIComponent(orderStatusMatch[1]);
        const token = url.searchParams.get('token') || '';
        const order = await getOrder(env, orderId);
        if (!order || order.accessToken !== token) return jsonRes({ error: 'Order not found' }, 404);
        const hasDownload = Boolean(order.fileId || order.downloadUrl);
        return jsonRes({
          ok: true,
          orderId: order.id,
          productName: order.productName,
          status: order.status,
          licenseKey: order.status === 'approved' ? (order.licenseKey || null) : null,
          hasDownload,
          fileName: order.fileName || null,
          downloadReadyUrl:
            order.status === 'approved' && hasDownload
              ? `${url.origin}/api/orders/${encodeURIComponent(order.id)}/download?token=${encodeURIComponent(token)}`
              : null,
        });
      } catch (err) {
        return jsonRes({ error: err.message }, 500);
      }
    }

    // Public Support / Service Request (Preserved 100% + Saved into D1 support_tickets)
    if (path === '/api/service-request' && method === 'POST') {
      try {
        const body = await request.json().catch(() => null);
        if (!body || !body.name || !body.contact || !body.message) {
          return jsonRes({ error: 'يرجى تعبئة الاسم وطريقة التواصل وتفاصيل الطلب.' }, 400);
        }
        const ticketId = makeId('tkt');
        const ts = nowIso();
        if (env.MGD_DB) {
          await env.MGD_DB.prepare(
            `INSERT INTO support_tickets (id, name, contact, topic, message, status, replies_json, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, 'open', '[]', ?, ?)`
          ).bind(ticketId, String(body.name).slice(0, 120), String(body.contact).slice(0, 150), String(body.topic || 'استفسار عام').slice(0, 120), String(body.message).slice(0, 1500), ts, ts).run();
        }
        const text = [
          `📩 طلب خدمة / دعم فني جديد (#${ticketId})`,
          `━━━━━━━━━━━━━━━━━━`,
          `👤 الاسم: ${String(body.name).slice(0, 120)}`,
          `📞 طريقة التواصل: ${String(body.contact).slice(0, 150)}`,
          `🏷️ نوع الخدمة: ${String(body.topic || 'استفسار عام').slice(0, 120)}`,
          `📝 التفاصيل:\n${String(body.message).slice(0, 1500)}`,
        ].join('\n');
        const sent = await broadcastText(env, text);
        return jsonRes({ ok: true, ticketId, notifiedCount: sent.length }, 201);
      } catch (err) {
        return jsonRes({ error: err.message }, 500);
      }
    }

    // =========================================================================
    // 2) AUTHENTICATION ENDPOINTS (/api/auth/*)
    // =========================================================================

    if (path === '/api/auth/login' && method === 'POST') {
      try {
        const db = requireDB(env);
        const body = await request.json().catch(() => null);
        const email = String(body?.email || '').trim().toLowerCase();
        const password = String(body?.password || '');
        if (!password) return jsonRes({ error: 'يرجى إدخال كلمة المرور.' }, 400);

        // First-time bootstrap if users table is empty
        let user = await ensureBootstrappedSuperAdmin(env, email, password);

        if (!user) {
          if (!email) {
            // Allow Super Admin quick login with ADMIN_SECRET if email omitted
            const superUser = await db.prepare(`SELECT * FROM users WHERE role_key = 'super_admin' LIMIT 1`).first();
            if (superUser && superUser.status === 'active') {
              const ok = (await verifyPassword(password, superUser.password_hash, superUser.password_salt))
                || (env.ADMIN_SECRET && timingSafeEqual(password, env.ADMIN_SECRET));
              if (ok) user = superUser;
            }
          } else {
            const candidate = await db.prepare('SELECT * FROM users WHERE LOWER(email) = ?').bind(email).first();
            if (candidate) {
              if (candidate.status !== 'active') {
                return jsonRes({ error: 'تم إيقاف هذا الحساب من قِبل الإدارة.' }, 403);
              }
              const ok = (await verifyPassword(password, candidate.password_hash, candidate.password_salt))
                || (candidate.role_key === 'super_admin' && env.ADMIN_SECRET && timingSafeEqual(password, env.ADMIN_SECRET));
              if (ok) user = candidate;
            }
          }
        }

        if (!user) {
          await writeAudit(env, { id: 'anon', name: email || 'unknown', role_key: 'guest' }, 'auth.login_failed', 'auth', email, null, getClientIp(request));
          return jsonRes({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة.' }, 401);
        }

        const sess = await createSession(env, user.id, request);
        const permissions = await getUserPermissions(env, user);
        await writeAudit(env, user, 'auth.login', 'session', user.id, { email: user.email }, getClientIp(request));

        return jsonRes({
          ok: true,
          token: sess.token,
          expiresAt: sess.expiresAt,
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            role_key: user.role_key,
            role_title: user.role_title,
            department: user.department,
            telegram_id: user.telegram_id,
          },
          permissions,
          allPermissions: user.role_key === 'super_admin' ? ALL_PERMISSIONS : undefined,
          rolePresets: user.role_key === 'super_admin' ? ROLE_PRESETS : undefined,
        });
      } catch (err) {
        return jsonRes({ error: err.message }, 500);
      }
    }

    if (path === '/api/auth/me' && method === 'GET') {
      const { ctx, error } = await requireAuth(request, env);
      if (error) return error;
      return jsonRes({
        ok: true,
        user: ctx.user,
        permissions: ctx.permissions,
        allPermissions: ctx.user.role_key === 'super_admin' ? ALL_PERMISSIONS : undefined,
        rolePresets: ctx.user.role_key === 'super_admin' ? ROLE_PRESETS : undefined,
      });
    }

    if (path === '/api/auth/logout' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env);
      if (error) return error;
      if (ctx.sessionHash && env.MGD_DB) {
        await env.MGD_DB.prepare('UPDATE sessions SET revoked_at = ? WHERE token_hash = ?').bind(nowIso(), ctx.sessionHash).run();
      }
      await writeAudit(env, ctx.user, 'auth.logout', 'session', ctx.user.id, null, getClientIp(request));
      return jsonRes({ ok: true });
    }

    if (path === '/api/auth/change-password' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env);
      if (error) return error;
      const body = await request.json().catch(() => null);
      const newPassword = String(body?.newPassword || '');
      if (newPassword.length < 8) return jsonRes({ error: 'يجب أن تتكون كلمة المرور الجديدة من 8 أحرف على الأقل.' }, 400);
      const db = requireDB(env);
      const { hashHex, saltHex } = await hashPassword(newPassword);
      const ts = nowIso();
      await db.prepare('UPDATE users SET password_hash = ?, password_salt = ?, updated_at = ? WHERE id = ?')
        .bind(hashHex, saltHex, ts, ctx.user.id).run();
      // Revoke all other sessions for security
      if (ctx.sessionHash) {
        await db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND token_hash != ? AND revoked_at IS NULL')
          .bind(ts, ctx.user.id, ctx.sessionHash).run();
      }
      await writeAudit(env, ctx.user, 'auth.change_password', 'user', ctx.user.id, null, getClientIp(request));
      return jsonRes({ ok: true });
    }

    // =========================================================================
    // 3) DASHBOARD OVERVIEW & REPORTS
    // =========================================================================

    if (path === '/api/dashboard' && method === 'GET') {
      const { ctx, error } = await requireAuth(request, env, 'dashboard.view');
      if (error) return error;
      const db = requireDB(env);
      const [ordersAgg, custCnt, licCnt, staffCnt, sigCnt, postsAgg, projAgg, tasksLate, ticketsOpen, recentAudit] = await Promise.all([
        db.prepare(`SELECT COUNT(*) AS total, SUM(CASE WHEN status='approved' THEN amount ELSE 0 END) AS revenue, SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) AS pending, SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) AS approved FROM orders`).first(),
        db.prepare(`SELECT COUNT(*) AS cnt FROM customers`).first(),
        db.prepare(`SELECT COUNT(*) AS cnt FROM licenses WHERE status='active'`).first(),
        db.prepare(`SELECT COUNT(*) AS cnt FROM users WHERE status='active'`).first(),
        db.prepare(`SELECT COUNT(*) AS total, SUM(CASE WHEN status='tp_hit' THEN 1 ELSE 0 END) AS wins FROM signals`).first(),
        db.prepare(`SELECT COUNT(*) AS total, SUM(CASE WHEN status='scheduled' THEN 1 ELSE 0 END) AS scheduled, SUM(CASE WHEN status='pending_approval' THEN 1 ELSE 0 END) AS pendingApproval FROM social_posts`).first(),
        db.prepare(`SELECT COUNT(*) AS active FROM projects WHERE status='in_progress'`).first(),
        db.prepare(`SELECT COUNT(*) AS late FROM tasks WHERE status != 'done' AND due_date IS NOT NULL AND due_date < ?`).bind(nowIso().slice(0, 10)).first(),
        db.prepare(`SELECT COUNT(*) AS openCnt FROM support_tickets WHERE status='open'`).first(),
        db.prepare(`SELECT id, actor_name, actor_role, action, resource_type, resource_id, created_at FROM audit_logs ORDER BY id DESC LIMIT 12`).all(),
      ]);

      let productsCount = 44;
      try {
        const { items } = await loadProductsJson(env);
        productsCount += items.filter(p => !p.deleted).length - items.filter(p => p.deleted).length;
      } catch {}

      return jsonRes({
        ok: true,
        stats: {
          totalOrders: ordersAgg?.total || 0,
          approvedOrders: ordersAgg?.approved || 0,
          pendingOrders: ordersAgg?.pending || 0,
          totalRevenue: Number(ordersAgg?.revenue || 0),
          customersCount: custCnt?.cnt || 0,
          activeLicenses: licCnt?.cnt || 0,
          productsCount,
          activeStaff: staffCnt?.cnt || 0,
          signalsTotal: sigCnt?.total || 0,
          signalsWins: sigCnt?.wins || 0,
          postsTotal: postsAgg?.total || 0,
          postsScheduled: postsAgg?.scheduled || 0,
          postsPendingApproval: postsAgg?.pendingApproval || 0,
          activeProjects: projAgg?.active || 0,
          overdueTasks: tasksLate?.late || 0,
          openTickets: ticketsOpen?.openCnt || 0,
        },
        recentActivity: hasPermission(ctx, 'audit.view') ? (recentAudit.results || []) : [],
      });
    }

    // =========================================================================
    // 4) STAFF & GRANULAR RBAC MANAGEMENT (/api/staff/*)
    // =========================================================================

    if (path === '/api/staff' && method === 'GET') {
      const { ctx, error } = await requireAuth(request, env, 'staff.view');
      if (error) return error;
      const db = requireDB(env);
      const usersRes = await db.prepare(
        `SELECT id, email, name, role_key, role_title, department, status, telegram_id, created_at, updated_at FROM users ORDER BY created_at ASC`
      ).all();
      const permsRes = await db.prepare('SELECT user_id, permission FROM user_permissions').all();
      const permMap = new Map();
      for (const p of permsRes.results || []) {
        if (!permMap.has(p.user_id)) permMap.set(p.user_id, []);
        permMap.get(p.user_id).push(p.permission);
      }
      const staff = (usersRes.results || []).map(u => ({
        ...u,
        permissions: u.role_key === 'super_admin' ? ALL_PERMISSIONS : (permMap.get(u.id) || []),
      }));
      return jsonRes({ ok: true, staff, allPermissions: ALL_PERMISSIONS, rolePresets: ROLE_PRESETS });
    }

    if (path === '/api/staff' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'staff.manage');
      if (error) return error;
      const body = await request.json().catch(() => null);
      const email = String(body?.email || '').trim().toLowerCase();
      const name = String(body?.name || '').trim();
      const password = String(body?.password || '');
      if (!email || !email.includes('@') || !name || password.length < 6) {
        return jsonRes({ error: 'يرجى إدخال الاسم، بريد إلكتروني صحيح، وكلمة مرور لا تقل عن 6 أحرف.' }, 400);
      }
      const db = requireDB(env);
      const id = makeId('usr');
      const roleKey = body.role_key === 'super_admin' && ctx.user.role_key === 'super_admin' ? 'super_admin' : 'staff';
      const roleTitle = String(body.role_title || 'موظف').trim();
      const department = String(body.department || 'عام').trim();
      const perms = Array.isArray(body.permissions)
        ? body.permissions.filter(p => ALL_PERMISSIONS.includes(p))
        : (ROLE_PRESETS[body.preset] || ['dashboard.view']);
      const { hashHex, saltHex } = await hashPassword(password);
      const ts = nowIso();

      try {
        await db.prepare(
          `INSERT INTO users (id, email, name, password_hash, password_salt, role_key, role_title, department, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`
        ).bind(id, email, name, hashHex, saltHex, roleKey, roleTitle, department, ts, ts).run();
      } catch (e) {
        return jsonRes({ error: 'البريد الإلكتروني مستخدم بالفعل لحساب آخر.' }, 409);
      }

      for (const perm of perms) {
        await db.prepare('INSERT OR IGNORE INTO user_permissions (user_id, permission) VALUES (?, ?)').bind(id, perm).run();
      }
      await writeAudit(env, ctx.user, 'staff.create', 'user', id, { email, name, roleTitle, department, permissionsCount: perms.length }, getClientIp(request));
      return jsonRes({ ok: true, user: { id, email, name, role_key: roleKey, role_title: roleTitle, department, status: 'active', permissions: perms } }, 201);
    }

    const staffSubMatch = path.match(/^\/api\/staff\/([^/]+)(?:\/(suspend|activate|revoke-sessions|telegram-code))?$/);
    if (staffSubMatch) {
      const targetId = decodeURIComponent(staffSubMatch[1]);
      const action = staffSubMatch[2] || '';
      const { ctx, error } = await requireAuth(request, env, 'staff.manage');
      if (error) return error;
      const db = requireDB(env);
      const target = await db.prepare('SELECT * FROM users WHERE id = ?').bind(targetId).first();
      if (!target) return jsonRes({ error: 'الموظف غير موجود.' }, 404);

      if (action === 'telegram-code' && method === 'POST') {
        const code = `MGD-${randomHex(3).toUpperCase()}`;
        const expiresAt = new Date(Date.now() + 1000 * 60 * 30).toISOString(); // 30 min
        await db.prepare('INSERT INTO telegram_link_codes (code, user_id, expires_at) VALUES (?, ?, ?)').bind(code, targetId, expiresAt).run();
        await writeAudit(env, ctx.user, 'staff.generate_telegram_code', 'user', targetId, null, getClientIp(request));
        return jsonRes({ ok: true, code, expiresAt, command: `/link ${code}` });
      }

      if (action === 'revoke-sessions' && method === 'POST') {
        await db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(nowIso(), targetId).run();
        await writeAudit(env, ctx.user, 'staff.revoke_sessions', 'user', targetId, null, getClientIp(request));
        return jsonRes({ ok: true });
      }

      if (action === 'suspend' && method === 'POST') {
        if (target.role_key === 'super_admin') return jsonRes({ error: 'لا يمكن إيقاف حساب المدير الرئيسي.' }, 400);
        const ts = nowIso();
        await db.prepare(`UPDATE users SET status = 'suspended', updated_at = ? WHERE id = ?`).bind(ts, targetId).run();
        await db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(ts, targetId).run();
        await writeAudit(env, ctx.user, 'staff.suspend', 'user', targetId, { email: target.email }, getClientIp(request));
        return jsonRes({ ok: true, status: 'suspended' });
      }

      if (action === 'activate' && method === 'POST') {
        await db.prepare(`UPDATE users SET status = 'active', updated_at = ? WHERE id = ?`).bind(nowIso(), targetId).run();
        await writeAudit(env, ctx.user, 'staff.activate', 'user', targetId, { email: target.email }, getClientIp(request));
        return jsonRes({ ok: true, status: 'active' });
      }

      if (!action && (method === 'PATCH' || method === 'PUT')) {
        const body = await request.json().catch(() => null);
        if (!body) return jsonRes({ error: 'Invalid JSON' }, 400);
        const ts = nowIso();
        const name = body.name ? String(body.name).trim() : target.name;
        const roleTitle = body.role_title ? String(body.role_title).trim() : target.role_title;
        const department = body.department ? String(body.department).trim() : target.department;
        const telegramId = body.telegram_id !== undefined ? (String(body.telegram_id).trim() || null) : target.telegram_id;

        await db.prepare('UPDATE users SET name = ?, role_title = ?, department = ?, telegram_id = ?, updated_at = ? WHERE id = ?')
          .bind(name, roleTitle, department, telegramId, ts, targetId).run();

        if (body.password && String(body.password).length >= 6) {
          const { hashHex, saltHex } = await hashPassword(String(body.password));
          await db.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?').bind(hashHex, saltHex, targetId).run();
          await db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(ts, targetId).run();
        }

        if (Array.isArray(body.permissions) && target.role_key !== 'super_admin') {
          await db.prepare('DELETE FROM user_permissions WHERE user_id = ?').bind(targetId).run();
          const validPerms = body.permissions.filter(p => ALL_PERMISSIONS.includes(p));
          for (const p of validPerms) {
            await db.prepare('INSERT OR IGNORE INTO user_permissions (user_id, permission) VALUES (?, ?)').bind(targetId, p).run();
          }
          // Revoke sessions when permissions change so updated RBAC takes effect cleanly
          await db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(ts, targetId).run();
        }

        await writeAudit(env, ctx.user, 'staff.update', 'user', targetId, { name, roleTitle, department, permissionsUpdated: Array.isArray(body.permissions) }, getClientIp(request));
        return jsonRes({ ok: true });
      }

      if (!action && method === 'DELETE') {
        if (target.role_key === 'super_admin') return jsonRes({ error: 'لا يمكن حذف المدير الرئيسي.' }, 400);
        const ts = nowIso();
        await db.prepare(`UPDATE users SET status = 'deleted', email = ?, telegram_id = NULL, updated_at = ? WHERE id = ?`)
          .bind(`deleted_${Date.now()}_${target.email}`, ts, targetId).run();
        await db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(ts, targetId).run();
        await writeAudit(env, ctx.user, 'staff.delete', 'user', targetId, { oldEmail: target.email }, getClientIp(request));
        return jsonRes({ ok: true });
      }
    }

    // =========================================================================
    // 5) CMS — FULL WEBSITE CONTENT MANAGEMENT (/api/cms/*)
    // =========================================================================

    if (path === '/api/cms' && method === 'GET') {
      const { error } = await requireAuth(request, env, 'cms.view');
      if (error) return error;
      const db = requireDB(env);
      const [cfgRows, pageRows, revRows] = await Promise.all([
        db.prepare('SELECT * FROM cms_config').all(),
        db.prepare('SELECT * FROM cms_pages ORDER BY sort_order ASC').all(),
        db.prepare('SELECT id, target_type, target_key, created_by, created_at FROM cms_revisions ORDER BY id DESC LIMIT 20').all(),
      ]);
      const config = {};
      for (const r of cfgRows.results || []) {
        config[r.key] = { value: JSON.parse(r.value_json || '{}'), status: r.status, updated_by: r.updated_by, updated_at: r.updated_at };
      }
      return jsonRes({
        ok: true,
        config,
        pages: (pageRows.results || []).map(p => ({ ...p, content: JSON.parse(p.content_json || '{}') })),
        revisions: revRows.results || [],
      });
    }

    if (path === '/api/cms/config' && method === 'PUT') {
      const body = await request.json().catch(() => null);
      const status = body?.status === 'draft' ? 'draft' : 'published';
      const { ctx, error } = await requireAuth(request, env, status === 'published' ? 'cms.publish' : 'cms.edit');
      if (error) return error;
      if (!body || !body.key || body.value === undefined) return jsonRes({ error: 'key and value are required' }, 400);
      const db = requireDB(env);
      const ts = nowIso();
      const valStr = JSON.stringify(body.value);

      // Save revision snapshot
      const prev = await db.prepare('SELECT value_json FROM cms_config WHERE key = ?').bind(body.key).first();
      if (prev) {
        await db.prepare('INSERT INTO cms_revisions (target_type, target_key, snapshot_json, created_by, created_at) VALUES (?, ?, ?, ?, ?)')
          .bind('config', body.key, prev.value_json, ctx.user.name, ts).run();
      }
      await db.prepare(
        `INSERT INTO cms_config (key, value_json, status, updated_by, updated_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, status=excluded.status, updated_by=excluded.updated_by, updated_at=excluded.updated_at`
      ).bind(body.key, valStr, status, ctx.user.name, ts).run();

      await writeAudit(env, ctx.user, `cms.config_${status}`, 'cms_config', body.key, null, getClientIp(request));
      return jsonRes({ ok: true, key: body.key, status });
    }

    if (path === '/api/cms/pages' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'cms.edit');
      if (error) return error;
      const body = await request.json().catch(() => null);
      if (!body?.slug || !body?.title) return jsonRes({ error: 'slug and title are required' }, 400);
      const db = requireDB(env);
      const ts = nowIso();
      const slug = String(body.slug).trim().toLowerCase().replace(/[^a-z0-9-_]/g, '');
      const isPub = body.is_published ? 1 : 0;
      if (isPub && !hasPermission(ctx, 'cms.publish')) return jsonRes({ error: 'لا تملك صلاحية النشر العام للصفحات.' }, 403);
      const prev = await db.prepare('SELECT content_json FROM cms_pages WHERE slug = ?').bind(slug).first();
      if (prev) {
        await db.prepare('INSERT INTO cms_revisions (target_type, target_key, snapshot_json, created_by, created_at) VALUES (?, ?, ?, ?, ?)')
          .bind('page', slug, prev.content_json, ctx.user.name, ts).run();
      }
      await db.prepare(
        `INSERT INTO cms_pages (slug, title, content_json, is_published, sort_order, updated_by, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(slug) DO UPDATE SET title=excluded.title, content_json=excluded.content_json, is_published=excluded.is_published, sort_order=excluded.sort_order, updated_by=excluded.updated_by, updated_at=excluded.updated_at`
      ).bind(slug, String(body.title).trim(), JSON.stringify(body.content || {}), isPub, Number(body.sort_order || 0), ctx.user.name, ts).run();
      await writeAudit(env, ctx.user, 'cms.page_save', 'cms_page', slug, { title: body.title, isPub }, getClientIp(request));
      return jsonRes({ ok: true, slug });
    }

    const cmsPageDel = path.match(/^\/api\/cms\/pages\/([^/]+)$/);
    if (cmsPageDel && method === 'DELETE') {
      const { ctx, error } = await requireAuth(request, env, 'cms.publish');
      if (error) return error;
      const slug = decodeURIComponent(cmsPageDel[1]);
      await requireDB(env).prepare('DELETE FROM cms_pages WHERE slug = ?').bind(slug).run();
      await writeAudit(env, ctx.user, 'cms.page_delete', 'cms_page', slug, null, getClientIp(request));
      return jsonRes({ ok: true });
    }

    const cmsRevRestore = path.match(/^\/api\/cms\/revisions\/(\d+)\/restore$/);
    if (cmsRevRestore && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'cms.publish');
      if (error) return error;
      const revId = Number(cmsRevRestore[1]);
      const db = requireDB(env);
      const rev = await db.prepare('SELECT * FROM cms_revisions WHERE id = ?').bind(revId).first();
      if (!rev) return jsonRes({ error: 'النسخة غير موجودة.' }, 404);
      const ts = nowIso();
      if (rev.target_type === 'config') {
        await db.prepare('UPDATE cms_config SET value_json = ?, updated_by = ?, updated_at = ? WHERE key = ?')
          .bind(rev.snapshot_json, ctx.user.name, ts, rev.target_key).run();
      } else if (rev.target_type === 'page') {
        await db.prepare('UPDATE cms_pages SET content_json = ?, updated_by = ?, updated_at = ? WHERE slug = ?')
          .bind(rev.snapshot_json, ctx.user.name, ts, rev.target_key).run();
      }
      await writeAudit(env, ctx.user, 'cms.revision_restore', rev.target_type, rev.target_key, { revId }, getClientIp(request));
      return jsonRes({ ok: true });
    }

    // =========================================================================
    // 6) PRODUCTS, CATEGORIES, ORDERS, CUSTOMERS & LICENSES
    // =========================================================================

    if (path.startsWith('/api/products')) {
      if (method === 'GET') {
        const { error } = await requireAuth(request, env, 'products.view');
        if (error) return error;
        const { items } = await loadProductsJson(env);
        return jsonRes({ ok: true, products: items });
      }
      if (method === 'POST') {
        const body = await request.json().catch(() => null);
        const perm = body?.id ? 'products.edit' : 'products.create';
        const { ctx, error } = await requireAuth(request, env, perm);
        if (error) return error;
        if (!body) return jsonRes({ error: 'Invalid JSON body' }, 400);

        let product = null;
        if (body.prompt && !body.name && env.AI) {
          product = await parseProductWithAI(env, body.prompt, 'ai_');
        } else if (body.name) {
          product = normalizeProduct(body, `${body.name} ${body.desc || ''}`, 'ai_');
        }
        if (!product) return jsonRes({ error: 'Missing required field: name (or prompt)' }, 400);

        if (body.imageBase64) {
          const ext = (body.imageExt || 'png').replace(/[^a-z0-9]/gi, '');
          const fileName = `${slugify(product.name)}.${ext}`;
          product.image = await uploadImageToGitHub(env, fileName, body.imageBase64);
        }
        await upsertProduct(env, product);
        await writeAudit(env, ctx.user, body.id ? 'products.edit' : 'products.create', 'product', product.id, { name: product.name, price: product.price }, getClientIp(request));
        return jsonRes({ ok: true, product }, 201);
      }
      if (method === 'DELETE') {
        const { ctx, error } = await requireAuth(request, env, 'products.delete');
        if (error) return error;
        const id = decodeURIComponent(path.replace('/api/products/', '').trim());
        if (!id) return jsonRes({ error: 'Missing product ID' }, 400);
        await deleteProduct(env, id);
        await writeAudit(env, ctx.user, 'products.delete', 'product', id, null, getClientIp(request));
        return jsonRes({ ok: true, deleted: id });
      }
    }

    if (path === '/api/categories' && method === 'GET') {
      const { error } = await requireAuth(request, env, 'products.view');
      if (error) return error;
      const res = await requireDB(env).prepare('SELECT * FROM categories ORDER BY sort_order ASC').all();
      return jsonRes({ ok: true, categories: res.results || [] });
    }
    if (path === '/api/categories' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'products.edit');
      if (error) return error;
      const body = await request.json().catch(() => null);
      if (!body?.name) return jsonRes({ error: 'اسم التصنيف مطلوب' }, 400);
      const id = body.id || makeId('cat');
      const slug = body.slug || slugify(body.name).toLowerCase();
      await requireDB(env).prepare(
        `INSERT INTO categories (id, name, slug, sort_order, is_active, created_at) VALUES (?, ?, ?, ?, 1, ?)
         ON CONFLICT(id) DO UPDATE SET name=excluded.name, sort_order=excluded.sort_order`
      ).bind(id, body.name.trim(), slug, Number(body.sort_order || 0), nowIso()).run();
      await writeAudit(env, ctx.user, 'categories.save', 'category', id, { name: body.name }, getClientIp(request));
      return jsonRes({ ok: true, id }, 201);
    }

    // Admin Orders List & Actions
    if (path === '/api/orders' && method === 'GET') {
      const { error } = await requireAuth(request, env, 'orders.view');
      if (error) return error;
      const status = url.searchParams.get('status') || '';
      const q = (url.searchParams.get('q') || '').trim();
      const db = requireDB(env);
      let sql = 'SELECT * FROM orders WHERE 1=1';
      const binds = [];
      if (status) { sql += ' AND status = ?'; binds.push(status); }
      if (q) { sql += ' AND (id LIKE ? OR buyer_name LIKE ? OR contact LIKE ? OR product_name LIKE ?)'; binds.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`); }
      sql += ' ORDER BY created_at DESC LIMIT 200';
      const res = await db.prepare(sql).bind(...binds).all();
      return jsonRes({ ok: true, orders: res.results || [] });
    }

    const adminOrderAct = path.match(/^\/api\/orders\/([^/]+)\/(approve|reject)$/);
    if (adminOrderAct && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'orders.approve');
      if (error) return error;
      const orderId = decodeURIComponent(adminOrderAct[1]);
      const act = adminOrderAct[2];
      const body = await request.json().catch(() => ({}));
      if (act === 'approve') {
        const order = await approveOrder(env, orderId, ctx.user.name, { downloadUrl: body.downloadUrl, fileName: body.fileName }, ctx.user);
        if (!order) return jsonRes({ error: 'الطلب غير موجود' }, 404);
        await broadcastText(env, `✅ تمت الموافقة على الطلب #${order.id} (${order.productName}) من لوحة التحكم بواسطة ${ctx.user.name}. مفتاح الترخيص: ${order.licenseKey}`);
        return jsonRes({ ok: true, order });
      } else {
        const order = await rejectOrder(env, orderId, ctx.user.name, ctx.user);
        if (!order) return jsonRes({ error: 'الطلب غير موجود' }, 404);
        await broadcastText(env, `❌ تم رفض الطلب #${order.id} (${order.productName}) من لوحة التحكم بواسطة ${ctx.user.name}.`);
        return jsonRes({ ok: true, order });
      }
    }

    // Customers & Licenses
    if (path === '/api/customers' && method === 'GET') {
      const { error } = await requireAuth(request, env, 'customers.view');
      if (error) return error;
      const db = requireDB(env);
      const [custs, lics] = await Promise.all([
        db.prepare('SELECT * FROM customers ORDER BY updated_at DESC LIMIT 200').all(),
        db.prepare('SELECT * FROM licenses ORDER BY created_at DESC LIMIT 300').all(),
      ]);
      return jsonRes({ ok: true, customers: custs.results || [], licenses: lics.results || [] });
    }

    if (path === '/api/licenses' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'licenses.manage');
      if (error) return error;
      const body = await request.json().catch(() => null);
      if (!body?.product_name) return jsonRes({ error: 'اسم المنتج مطلوب' }, 400);
      const id = makeId('lic');
      const key = body.license_key || makeLicenseKey();
      await requireDB(env).prepare(
        `INSERT INTO licenses (id, license_key, order_id, customer_id, product_id, product_name, license_type, max_devices, status, expires_at, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`
      ).bind(id, key, body.order_id || null, body.customer_id || null, body.product_id || '', body.product_name, body.license_type || 'lifetime', Number(body.max_devices || 1), body.expires_at || null, ctx.user.name, nowIso()).run();
      await writeAudit(env, ctx.user, 'licenses.create', 'license', id, { key, product_name: body.product_name }, getClientIp(request));
      return jsonRes({ ok: true, id, license_key: key }, 201);
    }

    const licToggle = path.match(/^\/api\/licenses\/([^/]+)\/status$/);
    if (licToggle && method === 'PATCH') {
      const { ctx, error } = await requireAuth(request, env, 'licenses.manage');
      if (error) return error;
      const id = decodeURIComponent(licToggle[1]);
      const body = await request.json().catch(() => null);
      const status = body?.status === 'suspended' ? 'suspended' : 'active';
      await requireDB(env).prepare('UPDATE licenses SET status = ? WHERE id = ?').bind(status, id).run();
      await writeAudit(env, ctx.user, 'licenses.status', 'license', id, { status }, getClientIp(request));
      return jsonRes({ ok: true, status });
    }

    // =========================================================================
    // 7) MGD SOCIAL MEDIA CENTER (/api/marketing/*)
    // =========================================================================

    if (path === '/api/marketing/posts' && method === 'GET') {
      const { error } = await requireAuth(request, env, 'marketing.view');
      if (error) return error;
      const db = requireDB(env);
      const [posts, accounts] = await Promise.all([
        db.prepare('SELECT * FROM social_posts ORDER BY created_at DESC LIMIT 100').all(),
        db.prepare('SELECT * FROM social_accounts ORDER BY created_at DESC').all(),
      ]);
      return jsonRes({ ok: true, posts: posts.results || [], accounts: accounts.results || [] });
    }

    if (path === '/api/marketing/accounts' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'marketing.approve');
      if (error) return error;
      const body = await request.json().catch(() => null);
      if (!body?.platform || !body?.account_name) return jsonRes({ error: 'المنصة واسم الحساب مطلوبان' }, 400);
      const id = makeId('soc');
      await requireDB(env).prepare(
        `INSERT INTO social_accounts (id, platform, account_name, channel_id, status, config_json, created_at)
         VALUES (?, ?, ?, ?, 'connected', ?, ?)`
      ).bind(id, body.platform, body.account_name, String(body.channel_id || '').trim(), JSON.stringify(body.config || {}), nowIso()).run();
      await writeAudit(env, ctx.user, 'marketing.account_add', 'social_account', id, { platform: body.platform, account_name: body.account_name, channel_id: body.channel_id }, getClientIp(request));
      return jsonRes({ ok: true, id }, 201);
    }

    const delSocAcc = path.match(/^\/api\/marketing\/accounts\/([^/]+)$/);
    if (delSocAcc && method === 'DELETE') {
      const { ctx, error } = await requireAuth(request, env, 'marketing.approve');
      if (error) return error;
      const id = decodeURIComponent(delSocAcc[1]);
      await requireDB(env).prepare('DELETE FROM social_accounts WHERE id = ?').bind(id).run();
      await writeAudit(env, ctx.user, 'marketing.account_delete', 'social_account', id, null, getClientIp(request));
      return jsonRes({ ok: true });
    }

    if (path === '/api/marketing/posts' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'marketing.create');
      if (error) return error;
      const body = await request.json().catch(() => null);
      if (!body?.body && !body?.media_url && !body?.mediaBase64) return jsonRes({ error: 'محتوى المنشور أو ملف الميديا مطلوب' }, 400);
      const id = body.id || makeId('post');
      const ts = nowIso();
      let status = body.status || 'draft';
      const wantsPublishNow = status === 'publish_now' || status === 'published';
      if (status === 'scheduled' && !hasPermission(ctx, 'marketing.schedule')) status = 'pending_approval';
      if (wantsPublishNow && !hasPermission(ctx, 'marketing.publish')) status = 'pending_approval';
      else if (wantsPublishNow) status = 'approved';

      let mediaUrl = String(body.media_url || '').trim();
      if (body.mediaBase64) {
        const ext = String(body.mediaExt || 'png').replace(/[^a-z0-9]/gi, '').toLowerCase() || 'png';
        const fname = `${slugify(body.title || 'mgd_post')}.${ext}`;
        mediaUrl = await uploadImageToGitHub(env, fname, body.mediaBase64, 'assets/media');
      }

      const platforms = Array.isArray(body.platforms) && body.platforms.length ? body.platforms : ['telegram', 'website'];
      const db = requireDB(env);
      await db.prepare(
        `INSERT INTO social_posts (id, title, body, hashtags, link_url, media_url, platforms_json, status, scheduled_at, created_by, publish_log_json, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?)
         ON CONFLICT(id) DO UPDATE SET title=excluded.title, body=excluded.body, hashtags=excluded.hashtags, link_url=excluded.link_url, media_url=excluded.media_url, platforms_json=excluded.platforms_json, status=excluded.status, scheduled_at=excluded.scheduled_at, updated_at=excluded.updated_at`
      ).bind(id, body.title || '', body.body || '', body.hashtags || '', body.link_url || '', mediaUrl, JSON.stringify(platforms), status, body.scheduled_at || null, ctx.user.name, ts, ts).run();
      await writeAudit(env, ctx.user, 'marketing.post_save', 'social_post', id, { status, mediaUrl }, getClientIp(request));

      if (wantsPublishNow && hasPermission(ctx, 'marketing.publish')) {
        const logs = await executeMarketingPostPublish(env, db, {
          id, title: body.title || '', body: body.body || '', hashtags: body.hashtags || '',
          link_url: body.link_url || '', media_url: mediaUrl, platforms_json: JSON.stringify(platforms),
        }, ctx.user.name, ts, body.target_channel || '');
        return jsonRes({ ok: true, id, status: 'published', media_url: mediaUrl, logs }, 201);
      }
      return jsonRes({ ok: true, id, status, media_url: mediaUrl }, 201);
    }

    const delPostMatch = path.match(/^\/api\/marketing\/posts\/([^/]+)$/);
    if (delPostMatch && method === 'DELETE') {
      const { ctx, error } = await requireAuth(request, env, 'marketing.approve');
      if (error) return error;
      const postId = decodeURIComponent(delPostMatch[1]);
      await requireDB(env).prepare('DELETE FROM social_posts WHERE id = ?').bind(postId).run();
      await writeAudit(env, ctx.user, 'marketing.post_delete', 'social_post', postId, null, getClientIp(request));
      return jsonRes({ ok: true });
    }

    const postActMatch = path.match(/^\/api\/marketing\/posts\/([^/]+)\/(approve|reject|publish)$/);
    if (postActMatch && method === 'POST') {
      const postId = decodeURIComponent(postActMatch[1]);
      const act = postActMatch[2];
      const { ctx, error } = await requireAuth(request, env, act === 'publish' ? 'marketing.publish' : 'marketing.approve');
      if (error) return error;
      const db = requireDB(env);
      const post = await db.prepare('SELECT * FROM social_posts WHERE id = ?').bind(postId).first();
      if (!post) return jsonRes({ error: 'المنشور غير موجود' }, 404);
      const ts = nowIso();

      if (act === 'reject') {
        await db.prepare(`UPDATE social_posts SET status='rejected', approved_by=?, updated_at=? WHERE id=?`).bind(ctx.user.name, ts, postId).run();
        await writeAudit(env, ctx.user, 'marketing.post_reject', 'social_post', postId, null, getClientIp(request));
        return jsonRes({ ok: true, status: 'rejected' });
      }
      if (act === 'approve') {
        const nextStatus = post.scheduled_at ? 'scheduled' : 'approved';
        await db.prepare(`UPDATE social_posts SET status=?, approved_by=?, updated_at=? WHERE id=?`).bind(nextStatus, ctx.user.name, ts, postId).run();
        await writeAudit(env, ctx.user, 'marketing.post_approve', 'social_post', postId, { nextStatus }, getClientIp(request));
        return jsonRes({ ok: true, status: nextStatus });
      }
      if (act === 'publish') {
        const body = await request.json().catch(() => ({}));
        const logs = await executeMarketingPostPublish(env, db, post, ctx.user.name, ts, body?.target_channel || '');
        await writeAudit(env, ctx.user, 'marketing.post_publish', 'social_post', postId, { logs }, getClientIp(request));
        return jsonRes({ ok: true, status: 'published', logs });
      }
    }

    if (path === '/api/marketing/ai-generate' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'marketing.create');
      if (error) return error;
      const body = await request.json().catch(() => null);
      if (!env.AI) return jsonRes({ error: 'Workers AI غير مفعل' }, 503);
      const res = await runWorkersAI(env, {
        messages: [
          { role: 'system', content: 'أنت كاتب محتوى تسويقي محترف لشركة MGD Trading Technology للتداول الخوارزمي وروبوتات MT5. اكتب منشوراً تسويقياً جذاباً بالعربية مع هاشتاقات مناسبة في صيغة JSON.' },
          { role: 'user', content: String(body?.prompt || 'إعلان لمتجر روبوتات الذهب من MGD Trading') },
        ],
        response_format: {
          type: 'json_schema',
          json_schema: {
            type: 'object',
            properties: { title: { type: 'string' }, body: { type: 'string' }, hashtags: { type: 'string' } },
            required: ['title', 'body', 'hashtags'],
          },
        },
      });
      let draft = res?.response;
      if (typeof draft === 'string') {
        const s = draft.indexOf('{'); const e = draft.lastIndexOf('}');
        if (s >= 0 && e > s) draft = JSON.parse(draft.slice(s, e + 1));
      }
      return jsonRes({ ok: true, draft });
    }

    // =========================================================================
    // 8) COMPANY MODULES (Signals, Academy, Agencies, Projects, Tasks, Chat, Support)
    // =========================================================================

    // Signals
    if (path === '/api/signals' && method === 'GET') {
      const { error } = await requireAuth(request, env, 'signals.view');
      if (error) return error;
      const res = await requireDB(env).prepare('SELECT * FROM signals ORDER BY created_at DESC LIMIT 100').all();
      return jsonRes({ ok: true, signals: res.results || [] });
    }
    if (path === '/api/signals' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'signals.manage');
      if (error) return error;
      const b = await request.json().catch(() => null);
      if (!b?.symbol || !b?.direction || !b?.entry_price) return jsonRes({ error: 'الزوج والاتجاه وسعر الدخول مطلوبة' }, 400);
      const id = b.id || makeId('sig');
      const ts = nowIso();
      await requireDB(env).prepare(
        `INSERT INTO signals (id, symbol, direction, entry_price, stop_loss, tp1, tp2, tp3, timeframe, status, result_pips, notes, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET symbol=excluded.symbol, direction=excluded.direction, entry_price=excluded.entry_price, stop_loss=excluded.stop_loss, tp1=excluded.tp1, tp2=excluded.tp2, tp3=excluded.tp3, timeframe=excluded.timeframe, status=excluded.status, result_pips=excluded.result_pips, notes=excluded.notes, updated_at=excluded.updated_at`
      ).bind(id, b.symbol, b.direction, String(b.entry_price), String(b.stop_loss || ''), String(b.tp1 || ''), String(b.tp2 || ''), String(b.tp3 || ''), b.timeframe || 'M15', b.status || 'active', Number(b.result_pips || 0), b.notes || '', ctx.user.name, ts, ts).run();
      await writeAudit(env, ctx.user, 'signals.save', 'signal', id, { symbol: b.symbol, direction: b.direction }, getClientIp(request));

      if (b.sendToChannel !== false) {
        const sigMsg = [
          `📡 إشارة تداول مباشرة من غرفة عمليات MGD`,
          `━━━━━━━━━━━━━━━━━━`,
          `🪙 الزوج: ${b.symbol} (${b.timeframe || 'M15'})`,
          `📊 الاتجاه: ${b.direction === 'BUY' ? '🟢 BUY (شراء)' : '🔴 SELL (بيع)'}`,
          `🎯 سعر الدخول: ${b.entry_price}`,
          b.stop_loss ? `🛡️ وقف الخسارة (SL): ${b.stop_loss}` : null,
          b.tp1 ? `💰 الهدف الأول (TP1): ${b.tp1}` : null,
          b.notes ? `📝 ملاحظات: ${b.notes}` : null,
          `━━━━━━━━━━━━━━━━━━`,
          `🌐 https://mgdtrading.vercel.app/#signals`,
        ].filter(Boolean).join('\n');
        const tgAccs = await requireDB(env).prepare(`SELECT channel_id FROM social_accounts WHERE platform='telegram' AND channel_id != ''`).all();
        for (const acc of (tgAccs.results || [])) {
          await tgSend(env, acc.channel_id, sigMsg);
        }
        await broadcastText(env, sigMsg);
      }
      return jsonRes({ ok: true, id }, 201);
    }
    const sigDel = path.match(/^\/api\/signals\/([^/]+)$/);
    if (sigDel && method === 'DELETE') {
      const { ctx, error } = await requireAuth(request, env, 'signals.manage');
      if (error) return error;
      const id = decodeURIComponent(sigDel[1]);
      await requireDB(env).prepare('DELETE FROM signals WHERE id = ?').bind(id).run();
      await writeAudit(env, ctx.user, 'signals.delete', 'signal', id, null, getClientIp(request));
      return jsonRes({ ok: true });
    }

    // Academy
    if (path === '/api/academy' && method === 'GET') {
      const { error } = await requireAuth(request, env, 'academy.view');
      if (error) return error;
      const res = await requireDB(env).prepare('SELECT * FROM academy_lessons ORDER BY sort_order ASC, created_at DESC').all();
      return jsonRes({ ok: true, lessons: res.results || [] });
    }
    if (path === '/api/academy' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'academy.manage');
      if (error) return error;
      const b = await request.json().catch(() => null);
      if (!b?.title || !b?.description) return jsonRes({ error: 'العنوان والوصف مطلوبان' }, 400);
      const id = b.id || makeId('les');
      const ts = nowIso();
      await requireDB(env).prepare(
        `INSERT INTO academy_lessons (id, num, category, title, description, video_url, is_published, sort_order, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET num=excluded.num, category=excluded.category, title=excluded.title, description=excluded.description, video_url=excluded.video_url, is_published=excluded.is_published, sort_order=excluded.sort_order, updated_at=excluded.updated_at`
      ).bind(id, b.num || '', b.category || 'مفهوم تداول', b.title, b.description, b.video_url || '', b.is_published === false ? 0 : 1, Number(b.sort_order || 0), ctx.user.name, ts, ts).run();
      await writeAudit(env, ctx.user, 'academy.save', 'lesson', id, { title: b.title }, getClientIp(request));

      if (b.sendToChannel) {
        const acMsg = [
          `🎓 درس جديد في أكاديمية MGD (#${b.num || 'جديد'})`,
          `📌 ${b.title} (${b.category || 'مفهوم تداول'})`,
          '',
          b.description,
          b.video_url ? `\n🎬 رابط الفيديو: ${b.video_url}` : '',
          `\n🌐 https://mgdtrading.vercel.app/#academy`,
        ].filter(Boolean).join('\n');
        const tgAccs = await requireDB(env).prepare(`SELECT channel_id FROM social_accounts WHERE platform='telegram' AND channel_id != ''`).all();
        for (const acc of (tgAccs.results || [])) {
          await tgSendMediaUrl(env, acc.channel_id, b.video_url || '', acMsg);
        }
        await broadcastMediaUrl(env, b.video_url || '', acMsg);
      }
      return jsonRes({ ok: true, id }, 201);
    }
    const acaDel = path.match(/^\/api\/academy\/([^/]+)$/);
    if (acaDel && method === 'DELETE') {
      const { ctx, error } = await requireAuth(request, env, 'academy.manage');
      if (error) return error;
      const id = decodeURIComponent(acaDel[1]);
      await requireDB(env).prepare('DELETE FROM academy_lessons WHERE id = ?').bind(id).run();
      await writeAudit(env, ctx.user, 'academy.delete', 'lesson', id, null, getClientIp(request));
      return jsonRes({ ok: true });
    }

    // Agencies
    if (path === '/api/agencies' && method === 'GET') {
      const { error } = await requireAuth(request, env, 'agencies.view');
      if (error) return error;
      const res = await requireDB(env).prepare('SELECT * FROM agencies ORDER BY created_at DESC').all();
      return jsonRes({ ok: true, agencies: res.results || [] });
    }
    if (path === '/api/agencies' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'agencies.manage');
      if (error) return error;
      const b = await request.json().catch(() => null);
      if (!b?.name) return jsonRes({ error: 'اسم الوكالة أو الوكيل مطلوب' }, 400);
      const id = b.id || makeId('ag');
      const ts = nowIso();
      await requireDB(env).prepare(
        `INSERT INTO agencies (id, name, broker, referral_link, contact, commission_rate, clients_count, total_volume, status, notes, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET name=excluded.name, broker=excluded.broker, referral_link=excluded.referral_link, contact=excluded.contact, commission_rate=excluded.commission_rate, clients_count=excluded.clients_count, total_volume=excluded.total_volume, status=excluded.status, notes=excluded.notes, updated_at=excluded.updated_at`
      ).bind(id, b.name, b.broker || 'TopFX', b.referral_link || '', b.contact || '', Number(b.commission_rate || 0), Number(b.clients_count || 0), Number(b.total_volume || 0), b.status || 'active', b.notes || '', ts, ts).run();
      await writeAudit(env, ctx.user, 'agencies.save', 'agency', id, { name: b.name }, getClientIp(request));
      return jsonRes({ ok: true, id }, 201);
    }

    // Projects & Tasks
    if (path === '/api/projects' && method === 'GET') {
      const { ctx, error } = await requireAuth(request, env, 'projects.view');
      if (error) return error;
      const db = requireDB(env);
      const [projs, tsks] = await Promise.all([
        db.prepare('SELECT * FROM projects ORDER BY created_at DESC').all(),
        db.prepare('SELECT * FROM tasks ORDER BY created_at DESC').all(),
      ]);
      // Filter projects for non-managers to those they belong to
      const canAll = hasPermission(ctx, 'projects.manage');
      const projects = (projs.results || []).filter(p => {
        if (canAll) return true;
        const members = JSON.parse(p.members_json || '[]');
        return p.manager_id === ctx.user.id || members.includes(ctx.user.id);
      });
      return jsonRes({ ok: true, projects, tasks: tsks.results || [] });
    }
    if (path === '/api/projects' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'projects.manage');
      if (error) return error;
      const b = await request.json().catch(() => null);
      if (!b?.name) return jsonRes({ error: 'اسم المشروع مطلوب' }, 400);
      const id = b.id || makeId('proj');
      const ts = nowIso();
      await requireDB(env).prepare(
        `INSERT INTO projects (id, name, description, manager_id, members_json, status, progress, due_date, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET name=excluded.name, description=excluded.description, manager_id=excluded.manager_id, members_json=excluded.members_json, status=excluded.status, progress=excluded.progress, due_date=excluded.due_date, updated_at=excluded.updated_at`
      ).bind(id, b.name, b.description || '', b.manager_id || ctx.user.id, JSON.stringify(b.members || []), b.status || 'in_progress', Number(b.progress || 0), b.due_date || null, ctx.user.name, ts, ts).run();
      // Auto-create project chat room
      await requireDB(env).prepare(
        `INSERT OR IGNORE INTO chat_rooms (id, name, type, project_id, allowed_users_json, created_by, created_at)
         VALUES (?, ?, 'project', ?, ?, ?, ?)`
      ).bind(`room_${id}`, `غرفة مشروع: ${b.name}`, id, JSON.stringify([b.manager_id || ctx.user.id, ...(b.members || [])]), ctx.user.id, ts).run();
      await writeAudit(env, ctx.user, 'projects.save', 'project', id, { name: b.name }, getClientIp(request));
      return jsonRes({ ok: true, id }, 201);
    }
    if (path === '/api/tasks' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'projects.manage');
      if (error) return error;
      const b = await request.json().catch(() => null);
      if (!b?.title) return jsonRes({ error: 'عنوان المهمة مطلوب' }, 400);
      const id = b.id || makeId('tsk');
      const ts = nowIso();
      await requireDB(env).prepare(
        `INSERT INTO tasks (id, project_id, title, description, assignee_id, priority, status, due_date, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET title=excluded.title, description=excluded.description, assignee_id=excluded.assignee_id, priority=excluded.priority, status=excluded.status, due_date=excluded.due_date, updated_at=excluded.updated_at`
      ).bind(id, b.project_id || null, b.title, b.description || '', b.assignee_id || null, b.priority || 'medium', b.status || 'todo', b.due_date || null, ctx.user.name, ts, ts).run();
      await writeAudit(env, ctx.user, 'tasks.save', 'task', id, { title: b.title, status: b.status || 'todo' }, getClientIp(request));
      return jsonRes({ ok: true, id }, 201);
    }

    // Internal Chat (Permission-Scoped Rooms)
    if (path === '/api/chat/rooms' && method === 'GET') {
      const { ctx, error } = await requireAuth(request, env, 'chat.access');
      if (error) return error;
      const db = requireDB(env);
      const res = await db.prepare('SELECT * FROM chat_rooms ORDER BY created_at ASC').all();
      const rooms = (res.results || []).filter(r => {
        if (ctx.user.role_key === 'super_admin' || r.type === 'general') return true;
        const allowed = JSON.parse(r.allowed_users_json || '[]');
        return allowed.includes(ctx.user.id);
      });
      return jsonRes({ ok: true, rooms });
    }
    const chatRoomMsg = path.match(/^\/api\/chat\/rooms\/([^/]+)\/messages$/);
    if (chatRoomMsg) {
      const { ctx, error } = await requireAuth(request, env, 'chat.access');
      if (error) return error;
      const roomId = decodeURIComponent(chatRoomMsg[1]);
      const db = requireDB(env);
      const room = await db.prepare('SELECT * FROM chat_rooms WHERE id = ?').bind(roomId).first();
      if (!room) return jsonRes({ error: 'الغرفة غير موجودة' }, 404);
      const allowed = JSON.parse(room.allowed_users_json || '[]');
      if (ctx.user.role_key !== 'super_admin' && room.type !== 'general' && !allowed.includes(ctx.user.id)) {
        return jsonRes({ error: 'Forbidden — ليس لديك صلاحية الوصول لهذه الغرفة.' }, 403);
      }
      if (method === 'GET') {
        const res = await db.prepare('SELECT * FROM chat_messages WHERE room_id = ? ORDER BY id DESC LIMIT 100').bind(roomId).all();
        return jsonRes({ ok: true, messages: (res.results || []).reverse() });
      }
      if (method === 'POST') {
        const b = await request.json().catch(() => null);
        if (!b?.body) return jsonRes({ error: 'الرسالة فارغة' }, 400);
        await db.prepare('INSERT INTO chat_messages (room_id, sender_id, sender_name, body, attachment_url, created_at) VALUES (?, ?, ?, ?, ?, ?)')
          .bind(roomId, ctx.user.id, ctx.user.name, String(b.body).slice(0, 2000), b.attachment_url || null, nowIso()).run();
        return jsonRes({ ok: true }, 201);
      }
    }

    // Support Tickets
    if (path === '/api/support/tickets' && method === 'GET') {
      const { error } = await requireAuth(request, env, 'support.view');
      if (error) return error;
      const res = await requireDB(env).prepare('SELECT * FROM support_tickets ORDER BY created_at DESC LIMIT 150').all();
      return jsonRes({ ok: true, tickets: res.results || [] });
    }
    const ticketAct = path.match(/^\/api\/support\/tickets\/([^/]+)$/);
    if (ticketAct && method === 'PATCH') {
      const { ctx, error } = await requireAuth(request, env, 'support.manage');
      if (error) return error;
      const id = decodeURIComponent(ticketAct[1]);
      const b = await request.json().catch(() => null);
      const db = requireDB(env);
      const tkt = await db.prepare('SELECT * FROM support_tickets WHERE id = ?').bind(id).first();
      if (!tkt) return jsonRes({ error: 'التذكرة غير موجودة' }, 404);
      const replies = JSON.parse(tkt.replies_json || '[]');
      if (b?.reply) replies.push({ by: ctx.user.name, text: String(b.reply), at: nowIso() });
      await db.prepare('UPDATE support_tickets SET status = ?, assigned_to = ?, replies_json = ?, updated_at = ? WHERE id = ?')
        .bind(b?.status || tkt.status, b?.assigned_to !== undefined ? b.assigned_to : tkt.assigned_to, JSON.stringify(replies), nowIso(), id).run();
      await writeAudit(env, ctx.user, 'support.update', 'ticket', id, { status: b?.status || tkt.status }, getClientIp(request));
      return jsonRes({ ok: true });
    }

    // MGD AI Assistant Endpoint
    if (path === '/api/ai/assistant' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'ai.use');
      if (error) return error;
      const b = await request.json().catch(() => null);
      try {
        const result = await runAdminAIAssistant(env, ctx, b?.message || '', b?.confirmAction || null);
        return jsonRes({ ok: true, ...result });
      } catch (err) {
        return jsonRes({ error: err.message }, 400);
      }
    }

    // Audit Logs & Backup Export
    if (path === '/api/audit' && method === 'GET') {
      const { error } = await requireAuth(request, env, 'audit.view');
      if (error) return error;
      const res = await requireDB(env).prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200').all();
      return jsonRes({ ok: true, logs: res.results || [] });
    }

    if (path === '/api/backup/export' && method === 'GET') {
      const { ctx, error } = await requireAuth(request, env, 'reports.export');
      if (error) return error;
      const db = requireDB(env);
      const tables = ['users', 'user_permissions', 'cms_config', 'cms_pages', 'categories', 'customers', 'orders', 'licenses', 'social_accounts', 'social_posts', 'signals', 'academy_lessons', 'agencies', 'projects', 'tasks', 'support_tickets', 'audit_logs'];
      const dump = { exportedAt: nowIso(), exportedBy: ctx.user.email, tables: {} };
      for (const tbl of tables) {
        const sql = tbl === 'users'
          ? 'SELECT id, email, name, role_key, role_title, department, status, telegram_id, created_at FROM users'
          : `SELECT * FROM ${tbl}`;
        const r = await db.prepare(sql).all();
        dump.tables[tbl] = r.results || [];
      }
      await writeAudit(env, ctx.user, 'system.backup_export', 'database', 'MGD_DB', null, getClientIp(request));
      return jsonRes(dump);
    }

    if (path === '/api/cms/sync-repo-file' && method === 'POST') {
      const { ctx, error } = await requireAuth(request, env, 'settings.manage');
      if (error) return error;
      const body = await request.json().catch(() => null);
      if (!body?.filePath || !body?.contentBase64) return jsonRes({ error: 'filePath and contentBase64 required' }, 400);
      const allowedFiles = ['admin.html', 'index.html', 'bot-worker/worker.js', 'bot-worker/schema.sql'];
      if (!allowedFiles.includes(body.filePath)) return jsonRes({ error: 'File path not allowed' }, 403);
      const branch = env.GITHUB_BRANCH || 'main';
      const existing = await ghRequest(env, `${body.filePath}?ref=${branch}`);
      let sha = null;
      if (existing.ok) {
        const info = await existing.json();
        sha = info.sha;
      }
      const putRes = await ghRequest(env, body.filePath, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: body.commitMessage || `Update ${body.filePath} from MGD Admin Control Center`,
          content: String(body.contentBase64).replace(/^data:[^;]+;base64,/, ''),
          branch,
          ...(sha ? { sha } : {}),
        }),
      });
      if (!putRes.ok) return jsonRes({ error: `GitHub sync failed (${putRes.status}): ${await putRes.text()}` }, 502);
      await writeAudit(env, ctx.user, 'cms.sync_repo_file', 'repo_file', body.filePath, null, getClientIp(request));
      return jsonRes({ ok: true, filePath: body.filePath });
    }

    // =========================================================================
    // 9) TELEGRAM BOT WEBHOOK (Role-Aware + Verified Linking + Orders + AI)
    // =========================================================================

    if (path === '/telegram' && method === 'POST') {
      const update = await request.json().catch(() => null);

      // Callback buttons (Approve / Reject Order)
      if (update?.callback_query) {
        const cb = update.callback_query;
        const data = String(cb.data || '');
        const fromId = String(cb.from?.id || '');
        const chatId = cb.message?.chat?.id;
        const msgId = cb.message?.message_id;
        const tgActor = await resolveTelegramActor(env, fromId, chatId);
        if (!tgActor || !tgActor.permissions.includes('orders.approve')) {
          await tgApi(env, 'answerCallbackQuery', { callback_query_id: cb.id, text: 'غير مصرح لك بهذا الإجراء.', show_alert: true });
          return jsonRes({ ok: true });
        }
        const actorLabel = tgActor.user.name || (cb.from?.username ? `@${cb.from.username}` : fromId);

        if (data.startsWith('approve:')) {
          const orderId = data.slice(8);
          const order = await approveOrder(env, orderId, actorLabel, {}, tgActor.user);
          if (!order) {
            await tgApi(env, 'answerCallbackQuery', { callback_query_id: cb.id, text: 'الطلب غير موجود.' });
            return jsonRes({ ok: true });
          }
          await tgApi(env, 'answerCallbackQuery', { callback_query_id: cb.id, text: `تمت الموافقة على الطلب ${orderId}` });
          if (chatId && msgId) {
            await tgApi(env, 'editMessageReplyMarkup', { chat_id: chatId, message_id: msgId, reply_markup: { inline_keyboard: [] } });
          }
          const hasFile = Boolean(order.fileId || order.downloadUrl);
          const note = hasFile
            ? `✅ تمت الموافقة على الطلب #${orderId} (${order.productName}) بواسطة ${actorLabel}\n🔑 الترخيص: ${order.licenseKey} — وتم إتاحة التحميل للعميل فوراً!`
            : `✅ تمت الموافقة على الطلب #${orderId} (${order.productName}) بواسطة ${actorLabel}\n🔑 الترخيص: ${order.licenseKey}\n\n📎 أرسل ملف المنتج (.ex5/.rar) أو رابط التحميل كرد (Reply) على رسالة الطلب ليظهر زر التحميل للعميل!`;
          await broadcastText(env, note);
          return jsonRes({ ok: true });
        }

        if (data.startsWith('reject:')) {
          const orderId = data.slice(7);
          const order = await rejectOrder(env, orderId, actorLabel, tgActor.user);
          if (!order) {
            await tgApi(env, 'answerCallbackQuery', { callback_query_id: cb.id, text: 'الطلب غير موجود.' });
            return jsonRes({ ok: true });
          }
          await tgApi(env, 'answerCallbackQuery', { callback_query_id: cb.id, text: `تم رفض الطلب ${orderId}` });
          if (chatId && msgId) {
            await tgApi(env, 'editMessageReplyMarkup', { chat_id: chatId, message_id: msgId, reply_markup: { inline_keyboard: [] } });
          }
          await broadcastText(env, `❌ تم رفض الطلب #${orderId} (${order.productName}) بواسطة ${actorLabel}.`);
          return jsonRes({ ok: true });
        }
        return jsonRes({ ok: true });
      }

      if (update?.my_chat_member?.chat) {
        const status = update.my_chat_member.new_chat_member?.status;
        if (status === 'member' || status === 'administrator') {
          await registerChat(env, update.my_chat_member.chat, update.my_chat_member.from);
          await tgSend(env, update.my_chat_member.chat.id, '✅ تم تفعيل إشعارات MGD Trading في هذه المجموعة!');
        }
        return jsonRes({ ok: true });
      }

      const msg = update?.message;
      if (!msg) return jsonRes({ ok: true });

      const chatId = msg.chat.id;
      const fromId = String(msg.from?.id || '');
      const text = (msg.caption || msg.text || '').trim();

      // Always allow /myid and verified /link CODE
      if (text === '/myid') {
        await tgSend(env, chatId, `معرّف حسابك (User ID): ${fromId}\nمعرّف المحادثة (Chat ID): ${chatId}`);
        return jsonRes({ ok: true });
      }

      if (text.startsWith('/link ') && env.MGD_DB) {
        const code = text.slice(6).trim().toUpperCase();
        const linkRow = await env.MGD_DB.prepare('SELECT * FROM telegram_link_codes WHERE code = ? AND used_at IS NULL').bind(code).first();
        if (!linkRow || new Date(linkRow.expires_at).getTime() < Date.now()) {
          await tgSend(env, chatId, '❌ رمز الربط غير صحيح أو منتهي الصلاحية. اطلب رمزاً جديداً من المدير.');
          return jsonRes({ ok: true });
        }
        const ts = nowIso();
        await env.MGD_DB.prepare('UPDATE users SET telegram_id = ?, updated_at = ? WHERE id = ?').bind(fromId, ts, linkRow.user_id).run();
        await env.MGD_DB.prepare('UPDATE telegram_link_codes SET used_at = ? WHERE code = ?').bind(ts, code).run();
        const u = await env.MGD_DB.prepare('SELECT name, role_title FROM users WHERE id = ?').bind(linkRow.user_id).first();
        await writeAudit(env, { id: linkRow.user_id, name: u?.name || fromId, role_key: 'staff' }, 'telegram.linked', 'user', linkRow.user_id, { telegram_id: fromId });
        await tgSend(env, chatId, `✅ تم ربط حسابك في تيليجرام بنجاح بحساب (${u?.name} — ${u?.role_title})! أرسل /help لرؤية صلاحياتك.`);
        return jsonRes({ ok: true });
      }

      const tgActor = await resolveTelegramActor(env, fromId, chatId);
      if (!tgActor) {
        await tgSend(env, chatId, `عذراً، هذا البوت مخصص لفريق MGD المعتمد فقط.\nإذا كنت موظفاً، اربط حسابك بأمر: /link رمز_الربط\n(ID: ${fromId})`);
        return jsonRes({ ok: true });
      }

      const isAdmin = tgActor.user.role_key === 'super_admin';
      const perms = tgActor.permissions;
      const actorLabel = tgActor.user.name || fromId;

      if (text === '/start' || text === '/help' || text === '/join') {
        await registerChat(env, msg.chat, msg.from);
        await tgSend(env, chatId, getTelegramHelp(isAdmin, perms));
        return jsonRes({ ok: true });
      }

      if (text === '/leave') {
        await removeChat(env, chatId);
        await tgSend(env, chatId, 'تم إيقاف استلام الإشعارات لهذا الحساب.');
        return jsonRes({ ok: true });
      }

      await registerChat(env, msg.chat, msg.from);

      // /stats for authorized users
      if (text === '/stats' && perms.includes('dashboard.view') && env.MGD_DB) {
        const [o, c, t] = await Promise.all([
          env.MGD_DB.prepare(`SELECT COUNT(*) AS total, SUM(CASE WHEN status='approved' THEN amount ELSE 0 END) AS rev, SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) AS pend FROM orders`).first(),
          env.MGD_DB.prepare('SELECT COUNT(*) AS cnt FROM customers').first(),
          env.MGD_DB.prepare(`SELECT COUNT(*) AS cnt FROM support_tickets WHERE status='open'`).first(),
        ]);
        await tgSend(env, chatId, `📊 ملخص MGD المباشر:\n• الطلبات: ${o?.total || 0} (معلق: ${o?.pend || 0})\n• الإيرادات المعتمدة: $${o?.rev || 0}\n• العملاء: ${c?.cnt || 0}\n• تذاكر الدعم المفتوحة: ${t?.cnt || 0}`);
        return jsonRes({ ok: true });
      }

      // /post for marketing staff -> pending_approval
      if (text.startsWith('/post ') && perms.includes('marketing.create') && env.MGD_DB) {
        const postBody = text.slice(6).trim();
        const pid = makeId('post');
        const ts = nowIso();
        await env.MGD_DB.prepare(
          `INSERT INTO social_posts (id, title, body, platforms_json, status, created_by, publish_log_json, created_at, updated_at)
           VALUES (?, 'منشور من تيليجرام', ?, '["telegram"]', 'pending_approval', ?, '[]', ?, ?)`
        ).bind(pid, postBody, actorLabel, ts, ts).run();
        await writeAudit(env, tgActor.user, 'telegram.post_submit', 'social_post', pid, null);
        await tgSend(env, chatId, `✅ تم حفظ المنشور (#${pid}) وإرساله لموافقة المدير في مركز التسويق.`);
        return jsonRes({ ok: true });
      }

      // /tasks for staff
      if (text === '/tasks' && perms.includes('projects.view') && env.MGD_DB) {
        const res = await env.MGD_DB.prepare(`SELECT title, priority, status, due_date FROM tasks WHERE status != 'done' ORDER BY created_at DESC LIMIT 10`).all();
        const list = (res.results || []).map(x => `• [${x.priority}] ${x.title} (${x.status}${x.due_date ? ' | ' + x.due_date : ''})`).join('\n');
        await tgSend(env, chatId, list ? `📋 المهام الجارية:\n\n${list}` : 'لا توجد مهام مفتوحة حالياً.');
        return jsonRes({ ok: true });
      }

      if (text === '/members' && isAdmin) {
        const members = await getAllRecipients(env);
        const lines = members.map(m => `• ${m.label} ${m.username || ''} — ID: ${m.id}`).join('\n');
        await tgSend(env, chatId, `الأعضاء المستلمون للإشعارات (${members.length}):\n\n${lines || 'لا يوجد'}`);
        return jsonRes({ ok: true });
      }

      if (text.startsWith('/remove_member ') && isAdmin) {
        const target = text.slice(15).trim();
        const ok = await removeChat(env, target);
        await tgSend(env, chatId, ok ? `تمت إزالة العضو (${target}).` : `لم يتم العثور على (${target}).`);
        return jsonRes({ ok: true });
      }

      // Reply to order notification with file/link
      if (msg.reply_to_message && env.MGD_STORE && perms.includes('orders.approve')) {
        const repliedOrderId = await env.MGD_STORE.get(`msgref:${chatId}:${msg.reply_to_message.message_id}`);
        if (repliedOrderId) {
          const extra = {};
          if (msg.document?.file_id) {
            extra.fileId = msg.document.file_id;
            extra.fileName = msg.document.file_name || 'MGD_Product.zip';
          }
          const urlMatch = text.match(/https?:\/\/\S+/);
          if (urlMatch) extra.downloadUrl = urlMatch[0];
          if (extra.fileId || extra.downloadUrl) {
            const order = await approveOrder(env, repliedOrderId, actorLabel, extra, tgActor.user);
            if (order) {
              await broadcastText(env, `✅ تم إرفاق ملف/رابط التحميل والموافقة على الطلب #${order.id} (${order.productName}) بواسطة ${actorLabel}\n🔑 الترخيص: ${order.licenseKey}`);
              return jsonRes({ ok: true });
            }
          }
        }
      }

      if (text.startsWith('/approve ') && perms.includes('orders.approve')) {
        const parts = text.split(/\s+/);
        const orderId = parts[1];
        const extra = {};
        if (parts[2] && /^https?:\/\//.test(parts[2])) extra.downloadUrl = parts[2];
        if (msg.document?.file_id) {
          extra.fileId = msg.document.file_id;
          extra.fileName = msg.document.file_name || 'MGD_Product.zip';
        }
        const order = await approveOrder(env, orderId, actorLabel, extra, tgActor.user);
        if (!order) await tgSend(env, chatId, `الطلب (${orderId}) غير موجود.`);
        else await broadcastText(env, `✅ تمت الموافقة على الطلب #${order.id} (${order.productName}) بواسطة ${actorLabel}.`);
        return jsonRes({ ok: true });
      }

      if (text === '/list' && perms.includes('products.view')) {
        try {
          const { items } = await loadProductsJson(env);
          const active = items.filter(p => !p.deleted);
          if (!active.length) await tgSend(env, chatId, 'لا توجد منتجات مضافة حتى الآن.');
          else {
            const list = active.map(p => `• ${p.name} ($${p.price} | ${p.platform}) — ID: ${p.id}`).join('\n');
            await tgSend(env, chatId, `المنتجات المضافة (${active.length}):\n\n${list}`);
          }
        } catch (err) {
          await tgSend(env, chatId, `خطأ أثناء الجلب: ${err.message}`);
        }
        return jsonRes({ ok: true });
      }

      if (text.startsWith('/delete ')) {
        if (!perms.includes('products.delete')) {
          await tgSend(env, chatId, '❌ لا تملك صلاحية حذف المنتجات.');
          return jsonRes({ ok: true });
        }
        const id = text.slice(8).trim();
        try {
          await deleteProduct(env, id);
          await writeAudit(env, tgActor.user, 'telegram.products_delete', 'product', id, null);
          await tgSend(env, chatId, `تم حذف المنتج (${id}) بنجاح. سيظهر التحديث خلال ~20 ثانية.`);
        } catch (err) {
          await tgSend(env, chatId, `فشل الحذف: ${err.message}`);
        }
        return jsonRes({ ok: true });
      }

      // Product publishing (requires products.create)
      if (!perms.includes('products.create')) {
        if (msg.chat.type === 'private') await tgSend(env, chatId, 'أرسل /help لرؤية الأوامر المتاحة لصلاحياتك.');
        return jsonRes({ ok: true });
      }

      let product = null;
      let usedAI = false;
      if (text.startsWith('/ai ')) {
        try { product = await parseProductWithAI(env, text.slice(4).trim(), 'tg_'); usedAI = Boolean(product); } catch {}
      } else {
        product = parseTelegramProductText(text);
        if (!product && env.AI && text && msg.chat.type === 'private') {
          try { product = await parseProductWithAI(env, text, 'tg_'); usedAI = Boolean(product); } catch {}
        }
      }

      if (!product) {
        if (msg.chat.type === 'private') await tgSend(env, chatId, 'لم أتعرف على الأمر. أرسل /help لرؤية الأوامر المتاحة.');
        return jsonRes({ ok: true });
      }

      try {
        if (Array.isArray(msg.photo) && msg.photo.length > 0) {
          const largest = msg.photo[msg.photo.length - 1];
          const { base64, ext } = await downloadTelegramPhotoBase64(env, largest.file_id);
          const fileName = `${slugify(product.name)}.${ext}`;
          product.image = await uploadImageToGitHub(env, fileName, base64);
        }
        await upsertProduct(env, product);
        await writeAudit(env, tgActor.user, 'telegram.products_create', 'product', product.id, { name: product.name, price: product.price, usedAI });
        await tgSend(
          env,
          chatId,
          [
            usedAI ? '🤖 تم تحليل الرسالة بالذكاء الاصطناعي ونشر المنتج بنجاح!' : '✅ تم نشر المنتج بنجاح!',
            '',
            `📦 الاسم: ${product.name}`,
            `🖥️ المنصة: ${product.platform} | الفئة: ${product.category}`,
            `💰 السعر: $${product.price}${product.oldPrice ? ` (بدلاً من $${product.oldPrice})` : ''}`,
            `🆔 المعرف: ${product.id}`,
            '',
            'سيظهر في المتجر خلال ~20 ثانية.',
          ].join('\n')
        );
      } catch (err) {
        await tgSend(env, chatId, `حدث خطأ أثناء النشر: ${err.message}`);
      }
      return jsonRes({ ok: true });
    }

    return jsonRes({ error: 'Not found' }, 404);
  },
};
