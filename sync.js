/**
 * 双端同步 · Cloudflare Pages Functions · KV 版
 * 路由：/functions/api/sync.js  →  https://你的域名/api/sync
 *
 * 需要在 Cloudflare 控制台绑定 KV 命名空间：
 * 1. 创建 KV 命名空间（比如叫 dashboard）
 * 2. 在 Pages 项目 → 设置 → 函数 → KV 命名空间绑定
 * 3. 变量名填 DASHBOARD_KV，选择刚才创建的命名空间
 */

const MAX_FAIL = 5;
const LOCK_MS = 5 * 60 * 1000;
const MAX_BYTES = 700 * 1024;

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' }
  });
}

/* key 里不放明文用户名——hash 一下别人就看不出谁是谁 */
async function hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function randSalt() {
  const a = new Uint8Array(16);
  crypto.getRandomValues(a);
  return Array.from(a).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** 与前端 Store.mergeList 同一套规则：按 id 取修改时间更新的那条 */
function mergeList(a, b) {
  const m = new Map();
  for (const it of [...(a || []), ...(b || [])]) {
    if (!it || !it.id) continue;
    const prev = m.get(it.id);
    if (!prev || (it._u || 0) > (prev._u || 0)) m.set(it.id, it);
  }
  return Array.from(m.values());
}

/** 服务端合并，消除「两端同时 push」的竞态。数组逐条合并，单值保留已有 */
function mergeAll(server, client) {
  const out = Object.assign({}, server || {});
  for (const [k, cv] of Object.entries(client || {})) {
    if (k.startsWith('_')) continue;
    const sv = out[k];
    if (Array.isArray(cv)) out[k] = mergeList(Array.isArray(sv) ? sv : [], cv);
    else if (sv === undefined || sv === null) out[k] = cv;
  }
  return out;
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const kv = env.DASHBOARD_KV;
  if (!kv) return json({ error: 'KV 存储未绑定，请在 Cloudflare 控制台设置' }, 500);

  let body;
  try { body = await request.json(); }
  catch { return json({ error: '请求格式不对' }, 400); }

  const user = String(body.user || '').trim().toLowerCase();
  const pass = String(body.pass || '');
  const action = String(body.action || 'pull');

  if (user.length < 3 || user.length > 32) return json({ error: '用户名需要 3-32 个字符' }, 400);
  if (pass.length < 8) return json({ error: '密码至少 8 位' }, 400);

  const uid = await hex('u|' + user);
  const kAuth = `auth/${uid}`;
  const kData = `data/${uid}`;
  const kRate = `rate/${uid}`;

  const get = async k => {
    try { return await kv.get(k, { type: 'json' }); }
    catch { return null; }
  };
  const setJSON = async (k, v) => {
    await kv.put(k, JSON.stringify(v));
  };

  // ── 限流：连续失败太多次就锁一段时间 ──
  const rate = (await get(kRate)) || { n: 0, until: 0 };
  const now = Date.now();
  if (rate.until && now < rate.until) {
    const mins = Math.ceil((rate.until - now) / 60000);
    return json({ error: `密码错误次数过多，请 ${mins} 分钟后再试` }, 429);
  }

  const auth = await get(kAuth);

  // ── 首次使用：把这个用户名注册下来 ──
  if (!auth) {
    if (action !== 'register' && action !== 'push') {
      return json({ error: 'NO_ACCOUNT' }, 404);
    }
    const salt = randSalt();
    await setJSON(kAuth, { salt, hash: await hex(pass + '|' + salt), createdAt: now });
    await setJSON(kData, body.data || {});
    return json({ ok: true, created: true, data: body.data || {} });
  }

  // ── 验密码 ──
  const h = await hex(pass + '|' + auth.salt);
  if (h !== auth.hash) {
    const n = (rate.n || 0) + 1;
    await setJSON(kRate, { n, until: n >= MAX_FAIL ? now + LOCK_MS : 0 });
    const left = MAX_FAIL - n;
    return json({ error: left > 0 ? `密码不对，还能试 ${left} 次` : '密码错误次数过多，已锁定 5 分钟' }, 401);
  }
  if (rate.n) await setJSON(kRate, { n: 0, until: 0 });

  // ── 改密码：只换验证信息，数据一动不动 ──
  if (action === 'chpass') {
    const np = String(body.newPass || '');
    if (np.length < 8) return json({ error: '新密码至少 8 位' }, 400);
    const salt = randSalt();
    await setJSON(kAuth, {
      salt, hash: await hex(np + '|' + salt), createdAt: auth.createdAt, changedAt: now
    });
    return json({ ok: true, changed: true });
  }

  // ── 拉 ──
  if (action === 'pull') {
    return json({ ok: true, data: (await get(kData)) || {} });
  }

  // ── 推：服务端合并后写回，并把合并结果返给客户端 ──
  if (action === 'push') {
    const raw = JSON.stringify(body.data || {});
    if (raw.length > MAX_BYTES) {
      return json({ error: '数据太大了（超过 700KB）。图片类内容不要参与同步' }, 413);
    }
    const merged = mergeAll((await get(kData)) || {}, body.data || {});
    await setJSON(kData, merged);
    return json({ ok: true, data: merged });
  }

  return json({ error: '未知操作' }, 400);
}

/** 浏览器预检 */
export function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: { 'access-control-allow-methods': 'POST, OPTIONS', 'access-control-allow-headers': 'content-type' }
  });
}
