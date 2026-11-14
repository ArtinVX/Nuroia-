// NUROIA_PANEL — per-user panel: dashboard + VLESS/WS tunnel + subscription
// Bindings: DB (D1), ADMIN_PASSWORD (secret), SESSION_KEY (secret)
import { connect } from 'cloudflare:sockets';

const GB = 1024 ** 3;
const DEFAULTS = {
  clean_ip: '', ip_pool: '', proxy_ip: '', prefix: 'Nuroia',
  frag_enabled: '1', frag_packets: 'tlshello', frag_length: '10-20', frag_interval: '10-20',
};
const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, sub_token TEXT UNIQUE NOT NULL,
    enabled INTEGER DEFAULT 1, quota_bytes INTEGER DEFAULT 0, used_bytes INTEGER DEFAULT 0,
    expire_at INTEGER DEFAULT 0, created_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT)`,
];
let schemaReady = null;
const ensureSchema = (env) =>
  (schemaReady ||= env.DB.batch(SCHEMA.map((s) => env.DB.prepare(s))).catch((e) => { schemaReady = null; throw e; }));

const json = (o, status = 200, h = {}) =>
  new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', ...h } });
const rand = (n, chars = '0123456789abcdef') =>
  [...crypto.getRandomValues(new Uint8Array(n))].map((x) => chars[x % chars.length]).join('');
const enc = new TextEncoder();

async function hmac(key, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return [...new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(msg)))].map((b) => b.toString(16).padStart(2, '0')).join('');
async function safeEq(a, b) {
  const x = await sha(a), y = await sha(b); let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}
async function isAuthed(req, env) {
  const m = (req.headers.get('cookie') || '').match(/(?:^|;\s*)nu_s=([^;]+)/);
  if (!m) return false;
  const [exp, sig] = m[1].split('.');
  if (!exp || !sig || +exp < Date.now()) return false;
  return safeEq(sig, await hmac(env.SESSION_KEY, exp));
}

async function getSettings(env) {
  const { results } = await env.DB.prepare('SELECT k,v FROM settings').all();
  const s = { ...DEFAULTS };
  for (const r of results) s[r.k] = r.v;
  return s;
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    try {
      await ensureSchema(env);
      if (req.headers.get('upgrade') === 'websocket') return vless(req, env, ctx);
      if (url.pathname.startsWith('/sub/')) return subscription(url, env);
      if (url.pathname.startsWith('/api/')) return api(req, url, env);
      return new Response(HTML, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
    } catch (e) {
      return json({ error: String(e && e.message) }, 500);
    }
  },
};

/* ───────────────────────── Admin API ───────────────────────── */
async function api(req, url, env) {
  const path = url.pathname.slice(4);
  if (path === '/login' && req.method === 'POST') {
    const { password } = await req.json().catch(() => ({}));
    if (typeof password === 'string' && (await safeEq(password, env.ADMIN_PASSWORD))) {
      const exp = String(Date.now() + 7 * 86400e3);
      const cookie = `nu_s=${exp}.${await hmac(env.SESSION_KEY, exp)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800`;
      return json({ ok: true }, 200, { 'set-cookie': cookie });
    }
    await new Promise((r) => setTimeout(r, 600));
    return json({ error: 'رمز اشتباه است' }, 401);
  }
  if (!(await isAuthed(req, env))) return json({ error: 'unauthorized' }, 401);
  if (req.method !== 'GET' && !(req.headers.get('content-type') || '').includes('application/json'))
    return json({ error: 'bad request' }, 400);

  if (path === '/state') {
    const { results } = await env.DB.prepare('SELECT * FROM users ORDER BY created_at DESC').all();
    return json({ users: results, settings: await getSettings(env), origin: url.origin, now: Date.now() });
  }
  if (path === '/logout') return json({ ok: true }, 200, { 'set-cookie': 'nu_s=; Path=/; Max-Age=0' });

  if (path === '/users' && req.method === 'POST') {
    const b = await req.json();
    const name = String(b.name || '').trim().slice(0, 60);
    if (!name) return json({ error: 'نام لازم است' }, 400);
    const quota = Math.max(0, Math.round((+b.quota_gb || 0) * GB));
    const days = Math.max(0, +b.days || 0);
    await env.DB.prepare('INSERT INTO users (id,name,sub_token,enabled,quota_bytes,used_bytes,expire_at,created_at) VALUES (?,?,?,?,?,?,?,?)')
      .bind(crypto.randomUUID(), name, rand(24), 1, quota, 0, days ? Date.now() + days * 86400e3 : 0, Date.now()).run();
    return json({ ok: true });
  }
  const m = path.match(/^\/users\/([0-9a-f-]{36})$/);
  if (m) {
    const id = m[1];
    if (req.method === 'DELETE') {
      await env.DB.prepare('DELETE FROM users WHERE id=?').bind(id).run();
      return json({ ok: true });
    }
    if (req.method === 'PATCH') {
      const b = await req.json();
      const set = [], vals = [];
      if (b.name !== undefined) { set.push('name=?'); vals.push(String(b.name).trim().slice(0, 60)); }
      if (b.enabled !== undefined) { set.push('enabled=?'); vals.push(b.enabled ? 1 : 0); }
      if (b.quota_gb !== undefined) { set.push('quota_bytes=?'); vals.push(Math.max(0, Math.round(+b.quota_gb * GB)) || 0); }
      if (b.days !== undefined) { set.push('expire_at=?'); vals.push(+b.days > 0 ? Date.now() + +b.days * 86400e3 : 0); }
      if (b.reset_usage) set.push('used_bytes=0');
      if (b.new_sub) { set.push('sub_token=?'); vals.push(rand(24)); }
      if (!set.length) return json({ error: 'nothing' }, 400);
      await env.DB.prepare(`UPDATE users SET ${set.join(',')} WHERE id=?`).bind(...vals, id).run();
      return json({ ok: true });
    }
  }
  if (path === '/settings' && req.method === 'POST') {
    const b = await req.json();
    const stmts = [];
    for (const k of Object.keys(DEFAULTS)) {
      if (b[k] === undefined) continue;
      let v = String(b[k]).slice(0, 4000).trim();
      if (k === 'frag_enabled') v = b[k] ? '1' : '0';
      if (k === 'frag_packets' && !/^(tlshello|1-3|\d+-\d+)$/.test(v)) v = 'tlshello';
      if ((k === 'frag_length' || k === 'frag_interval') && !/^\d+(-\d+)?$/.test(v)) v = '10-20';
      stmts.push(env.DB.prepare('INSERT INTO settings (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').bind(k, v));
    }
    if (stmts.length) await env.DB.batch(stmts);
    return json({ ok: true });
  }
  return json({ error: 'not found' }, 404);
}

/* ───────────────────────── Subscription ───────────────────────── */
function parseAddr(s) {
  s = s.trim();
  if (!s || s.startsWith('#')) return null;
  let m = s.match(/^\[([^\]]+)\]:(\d+)$/);
  if (m) return { addr: m[1], port: +m[2] };
  if (s.startsWith('[') && s.endsWith(']')) return { addr: s.slice(1, -1), port: 443 };
  if ((s.match(/:/g) || []).length === 1) { const [a, p] = s.split(':'); return { addr: a, port: +p || 443 }; }
  return { addr: s, port: 443 };
}
const hostFmt = (a) => (a.includes(':') ? `[${a}]` : a);

async function subscription(url, env) {
  const token = url.pathname.split('/')[2] || '';
  const u = await env.DB.prepare('SELECT * FROM users WHERE sub_token=?').bind(token).first();
  if (!u) return new Response('not found', { status: 404 });
  const s = await getSettings(env);
  const host = url.hostname;
  const seen = new Set(), list = [];
  for (const line of [s.clean_ip, ...s.ip_pool.split(/[\n,\s]+/), host]) {
    const p = parseAddr(line || '');
    if (!p) continue;
    const key = p.addr + ':' + p.port;
    if (!seen.has(key)) { seen.add(key); list.push(p); }
  }
  const label = (i) => `${s.prefix}-${u.name}-${i + 1}`;
  const headers = {
    'cache-control': 'no-store',
    'profile-update-interval': '6',
    'profile-title': 'Nuroia',
    'subscription-userinfo': `upload=0; download=${u.used_bytes}; total=${u.quota_bytes}; expire=${u.expire_at ? Math.floor(u.expire_at / 1000) : 0}`,
  };
  if (url.searchParams.get('format') === 'xray') {
    const frag = s.frag_enabled === '1';
    const configs = list.map((p, i) => ({
      remarks: label(i),
      log: { loglevel: 'warning' },
      dns: { servers: ['1.1.1.1', '8.8.8.8'] },
      inbounds: [
        { tag: 'socks', port: 10808, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true }, sniffing: { enabled: true, destOverride: ['http', 'tls'] } },
        { tag: 'http', port: 10809, listen: '127.0.0.1', protocol: 'http' },
      ],
      outbounds: [
        {
          tag: 'proxy', protocol: 'vless',
          settings: { vnext: [{ address: p.addr, port: p.port, users: [{ id: u.id, encryption: 'none' }] }] },
          streamSettings: {
            network: 'ws', security: 'tls',
            tlsSettings: { serverName: host, fingerprint: 'chrome', alpn: ['http/1.1'] },
            wsSettings: { path: '/ws', headers: { Host: host } },
            ...(frag ? { sockopt: { dialerProxy: 'fragment' } } : {}),
          },
        },
        ...(frag ? [{ tag: 'fragment', protocol: 'freedom', settings: { fragment: { packets: s.frag_packets, length: s.frag_length, interval: s.frag_interval } }, streamSettings: { sockopt: { tcpNoDelay: true } } }] : []),
        { tag: 'direct', protocol: 'freedom' },
        { tag: 'block', protocol: 'blackhole' },
      ],
      routing: { domainStrategy: 'IPIfNonMatch', rules: [] },
    }));
    return new Response(JSON.stringify(configs), { headers: { ...headers, 'content-type': 'application/json' } });
  }
  const links = list.map((p, i) =>
    `vless://${u.id}@${hostFmt(p.addr)}:${p.port}?encryption=none&security=tls&sni=${host}&fp=chrome&alpn=http%2F1.1&type=ws&host=${host}&path=%2Fws#${encodeURIComponent(label(i))}`);
  return new Response(btoa(links.join('\n')), { headers: { ...headers, 'content-type': 'text/plain; charset=utf-8' } });
}

/* ───────────────────────── VLESS over WebSocket ───────────────────────── */
function parseVless(b) {
  if (b.byteLength < 24) return null;
  const hex = [...b.subarray(1, 17)].map((x) => x.toString(16).padStart(2, '0')).join('');
  const uuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  let p = 18 + b[17];
  const cmd = b[p++];
  const port = (b[p] << 8) | b[p + 1]; p += 2;
  const t = b[p++];
  let addr;
  if (t === 1) { addr = b.subarray(p, p + 4).join('.'); p += 4; }
  else if (t === 2) { const l = b[p++]; addr = new TextDecoder().decode(b.subarray(p, p + l)); p += l; }
  else if (t === 3) {
    const dv = new DataView(b.buffer, b.byteOffset + p, 16), parts = [];
    for (let i = 0; i < 8; i++) parts.push(dv.getUint16(i * 2).toString(16));
    addr = parts.join(':'); p += 16;
  } else return null;
  return { version: b[0], uuid, cmd, port, addr, offset: p };
}

function vless(req, env, ctx) {
  const [client, server] = Object.values(new WebSocketPair());
  server.accept();
  let user = null, writer = null, sock = null, closed = false, udp = false, sentHdr = false;
  let version = 0, pending = 0, session = 0, chain = Promise.resolve();

  const flush = async () => {
    const n = pending;
    if (!n || !user) return;
    pending = 0;
    try { await env.DB.prepare('UPDATE users SET used_bytes=used_bytes+? WHERE id=?').bind(n, user.id).run(); } catch {}
  };
  const timer = setInterval(() => ctx.waitUntil(flush()), 60000);
  const close = () => {
    if (closed) return;
    closed = true; clearInterval(timer);
    try { sock && sock.close(); } catch {}
    try { server.close(1000); } catch {}
    ctx.waitUntil(flush());
  };
  const count = (n) => {
    pending += n; session += n;
    if (user.quota_bytes && user.used_bytes + session >= user.quota_bytes) close();
    else if (pending >= 2 * 1024 * 1024) ctx.waitUntil(flush());
  };
  const down = (c) => {
    if (closed) return;
    count(c.byteLength);
    if (!sentHdr) {
      sentHdr = true;
      const o = new Uint8Array(2 + c.byteLength); o[0] = version; o[1] = 0; o.set(c, 2);
      server.send(o);
    } else server.send(c);
  };

  async function dnsQuery(buf) {
    let i = 0;
    while (i + 2 <= buf.length) {
      const l = (buf[i] << 8) | buf[i + 1];
      const pkt = buf.subarray(i + 2, i + 2 + l); i += 2 + l;
      const r = await fetch('https://1.1.1.1/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: pkt });
      const a = new Uint8Array(await r.arrayBuffer());
      const o = new Uint8Array(2 + a.length); o[0] = a.length >> 8; o[1] = a.length & 255; o.set(a, 2);
      down(o);
    }
  }

  async function onMsg(data) {
    if (closed || typeof data === 'string') return;
    const buf = new Uint8Array(data);
    if (user) {
      count(buf.byteLength);
      if (udp) return dnsQuery(buf);
      if (writer) await writer.write(buf);
      return;
    }
    const h = parseVless(buf);
    if (!h) return close();
    const u = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(h.uuid).first();
    if (!u || !u.enabled || (u.expire_at && u.expire_at < Date.now()) || (u.quota_bytes && u.used_bytes >= u.quota_bytes)) return close();
    user = u; version = h.version;
    const first = buf.subarray(h.offset);
    count(first.byteLength);
    if (h.cmd === 2) {                       // UDP: فقط DNS
      if (h.port !== 53) return close();
      udp = true;
      return dnsQuery(first);
    }
    if (h.cmd !== 1) return close();
    const settings = await getSettings(env);
    const dial = async (host, retry) => {
      const s = connect({ hostname: host, port: h.port });
      sock = s; writer = s.writable.getWriter();
      let got = false, ended = false;
      const end = () => {
        if (ended) return; ended = true;
        if (!got && retry && !closed && settings.proxy_ip) {
          try { writer.releaseLock(); } catch {}
          const p = parseAddr(settings.proxy_ip);
          dial(p ? p.addr : settings.proxy_ip, false).catch(close);
        } else close();
      };
      s.readable.pipeTo(new WritableStream({ write(c) { got = true; down(c); } })).then(end, end);
      if (first.byteLength) { try { await writer.write(first); } catch {} }
    };
    await dial(h.addr, true);
  }

  server.addEventListener('message', (e) => { chain = chain.then(() => onMsg(e.data)).catch(close); });
  server.addEventListener('close', close);
  server.addEventListener('error', close);
  return new Response(null, { status: 101, webSocket: client });
}

/* ───────────────────────── Dashboard UI ───────────────────────── */
const HTML = String.raw`<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Nuroia Panel</title>
<style>
:root{--bg:#0b0f17;--card:#141a26;--bd:#232c3d;--tx:#e8edf5;--mut:#8b97ad;--ac:#4f8cff;--ok:#2ecc8f;--bad:#ff5d6c;--warn:#f5b84a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.7 Tahoma,Vazirmatn,system-ui,sans-serif}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid var(--bd);position:sticky;top:0;background:var(--bg);z-index:5}
.logo{font-weight:800;letter-spacing:3px;color:var(--ac)}
main{max-width:760px;margin:0 auto;padding:14px}
.tabs{display:flex;gap:6px;margin-bottom:14px;overflow-x:auto}
.tabs button{flex:1;white-space:nowrap}
button,input,select,textarea{font:inherit;color:var(--tx);background:#0f1522;border:1px solid var(--bd);border-radius:10px;padding:8px 12px}
button{cursor:pointer}button.pri{background:var(--ac);border-color:var(--ac);color:#fff}button.on{border-color:var(--ac);color:var(--ac)}
button.dng{color:var(--bad)}input,select,textarea{width:100%}textarea{min-height:110px;direction:ltr;font-family:monospace}
.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:14px;margin-bottom:12px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.row>*{flex:1;min-width:110px}.row>.fit{flex:0 0 auto;min-width:0}
.mut{color:var(--mut);font-size:12px}h3{margin:0 0 10px}label{display:block;margin:10px 0 4px;color:var(--mut);font-size:12px}
.bar{height:8px;background:#0f1522;border-radius:6px;overflow:hidden;margin:8px 0}.bar i{display:block;height:100%;background:var(--ac)}
.b{padding:1px 8px;border-radius:20px;font-size:11px;border:1px solid}.b.ok{color:var(--ok)}.b.bad{color:var(--bad)}.b.warn{color:var(--warn)}
.login{max-width:340px;margin:18vh auto}.login input,.login button{margin-top:10px}
#toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#000c;padding:8px 16px;border-radius:20px;display:none}
.acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.acts button{padding:5px 10px;font-size:12px}
</style></head><body>
<header><span class="logo">NUROIA</span><button id="out" style="display:none">خروج</button></header>
<main id="root"></main><div id="toast"></div>
<script>
const $=(s)=>document.querySelector(s);
const el=(t,a,...c)=>{const e=document.createElement(t);for(const k in(a||{})){if(k==='class')e.className=a[k];else if(k.slice(0,2)==='on')e.addEventListener(k.slice(2),a[k]);else if(k==='value')e.value=a[k];else if(a[k]!==false&&a[k]!=null)e.setAttribute(k,a[k]);}
c.flat().forEach(x=>e.append(x instanceof Node?x:document.createTextNode(x==null?'':x)));return e;};
const root=$('#root');let S=null,tab='users';
function toast(m){const t=$('#toast');t.textContent=m;t.style.display='block';clearTimeout(toast.t);toast.t=setTimeout(()=>t.style.display='none',2200);}
async function api(p,method,body){const r=await fetch('/api'+p,{method:method||'GET',headers:{'content-type':'application/json'},body:body?JSON.stringify(body):undefined});
 if(r.status===401&&p!=='/login'){login();throw new Error('auth');}const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||'خطا');return j;}
const run=async(f)=>{try{await f();}catch(e){if(e.message!=='auth')toast(e.message);}};
const fb=(b)=>{if(!b)return '0 B';const u=['B','KB','MB','GB','TB'];const i=Math.min(4,Math.floor(Math.log(b)/Math.log(1024)));return (b/Math.pow(1024,i)).toFixed(i?2:0)+' '+u[i];};
const fd=(t)=>t?new Date(t).toLocaleDateString('fa-IR'):'نامحدود';
async function copy(t){try{await navigator.clipboard.writeText(t);toast('کپی شد');}catch(e){prompt('کپی کنید:',t);}}

function login(){$('#out').style.display='none';const pw=el('input',{type:'password',placeholder:'رمز پنل',autocomplete:'current-password'});
 const go=()=>run(async()=>{await api('/login','POST',{password:pw.value});load();});
 pw.addEventListener('keydown',e=>{if(e.key==='Enter')go();});
 root.replaceChildren(el('div',{class:'card login'},el('h3',{},'ورود به پنل'),pw,el('button',{class:'pri',style:'width:100%',onclick:go},'ورود')));}
async function load(){await run(async()=>{S=await api('/state');$('#out').style.display='';render();});}
$('#out').onclick=()=>run(async()=>{await api('/logout','POST',{});login();});

function render(){const t=[['users','کاربران'],['ips','IP تمیز و استخر'],['set','فرگمنت و تنظیمات']];
 root.replaceChildren(el('div',{class:'tabs'},t.map(([k,n])=>el('button',{class:tab===k?'on':'',onclick:()=>{tab=k;render();}},n))),
 tab==='users'?usersView():tab==='ips'?ipsView():setView());}

function status(u){if(!u.enabled)return['غیرفعال','bad'];if(u.expire_at&&u.expire_at<S.now)return['منقضی','bad'];
 if(u.quota_bytes&&u.used_bytes>=u.quota_bytes)return['اتمام حجم','warn'];return['فعال','ok'];}
function usersView(){
 const n=el('input',{placeholder:'نام کاربر'}),g=el('input',{type:'number',min:'0',step:'any',placeholder:'حجم (GB) — 0 = نامحدود'}),d=el('input',{type:'number',min:'0',placeholder:'مدت (روز) — 0 = نامحدود'});
 const add=el('div',{class:'card'},el('h3',{},'کاربر جدید'),el('div',{class:'row'},n,g,d,el('button',{class:'pri fit',onclick:()=>run(async()=>{await api('/users','POST',{name:n.value,quota_gb:g.value,days:d.value});await load();toast('ساخته شد');})},'افزودن')));
 const tot=S.users.reduce((a,u)=>a+u.used_bytes,0);
 const sum=el('div',{class:'card row'},el('div',{},el('div',{class:'mut'},'کاربران'),S.users.length),el('div',{},el('div',{class:'mut'},'فعال'),S.users.filter(u=>status(u)[1]==='ok').length),el('div',{},el('div',{class:'mut'},'مصرف کل'),fb(tot)));
 const cards=S.users.map(u=>{const[st,cl]=status(u);const pct=u.quota_bytes?Math.min(100,u.used_bytes/u.quota_bytes*100):0;
  const sub=S.origin+'/sub/'+u.sub_token;
  return el('div',{class:'card'},el('div',{class:'row'},el('b',{},u.name),el('span',{class:'b '+cl+' fit'},st)),
   el('div',{class:'bar'},el('i',{style:'width:'+pct+'%'})),
   el('div',{class:'mut'},fb(u.used_bytes)+' / '+(u.quota_bytes?fb(u.quota_bytes):'نامحدود')+'  •  انقضا: '+fd(u.expire_at)),
   el('div',{class:'acts'},
    el('button',{onclick:()=>copy(sub)},'لینک اشتراک'),
    el('button',{onclick:()=>copy(sub+'?format=xray')},'اشتراک JSON (فرگمنت)'),
    el('button',{onclick:()=>run(async()=>{await api('/users/'+u.id,'PATCH',{enabled:!u.enabled});load();})},u.enabled?'غیرفعال':'فعال‌سازی'),
    el('button',{onclick:()=>{const q=prompt('حجم جدید (GB) — 0 نامحدود',u.quota_bytes?(u.quota_bytes/1073741824):0);if(q===null)return;
      const dd=prompt('مدت از امروز (روز) — 0 نامحدود',0);if(dd===null)return;run(async()=>{await api('/users/'+u.id,'PATCH',{quota_gb:+q,days:+dd});load();});}},'ویرایش حجم/زمان'),
    el('button',{onclick:()=>run(async()=>{await api('/users/'+u.id,'PATCH',{reset_usage:true});load();})},'ریست مصرف'),
    el('button',{onclick:()=>{if(confirm('لینک اشتراک قبلی باطل شود؟'))run(async()=>{await api('/users/'+u.id,'PATCH',{new_sub:true});load();});}},'لینک جدید'),
    el('button',{class:'dng',onclick:()=>{if(confirm('حذف '+u.name+'؟'))run(async()=>{await api('/users/'+u.id,'DELETE');load();});}},'حذف')));});
 return el('div',{},add,sum,cards.length?cards:el('div',{class:'mut'},'هنوز کاربری ندارید.'));}

function ipsView(){
 const c=el('input',{value:S.settings.clean_ip,placeholder:'مثلا 104.16.1.1 یا 104.16.1.1:2053',style:'direction:ltr'});
 const p=el('textarea',{placeholder:'هر خط یک IP یا دامنه (اختیاری :پورت)'});p.value=S.settings.ip_pool;
 const x=el('input',{value:S.settings.proxy_ip,placeholder:'اختیاری — برای سایت‌های پشت کلودفلر',style:'direction:ltr'});
 return el('div',{class:'card'},el('h3',{},'IP تمیز'),el('div',{class:'mut'},'آدرسی که اولین کانفیگ با آن ساخته می‌شود. خالی = فقط دامنه worker.'),c,
  el('label',{},'استخر IP'),el('div',{class:'mut'},'برای هر ورودی یک کانفیگ در اشتراک ساخته می‌شود (پورت‌های TLS کلودفلر: 443, 2053, 2083, 2087, 2096, 8443).'),p,
  el('label',{},'Proxy IP (Fallback)'),x,
  el('button',{class:'pri',style:'margin-top:14px;width:100%',onclick:()=>run(async()=>{await api('/settings','POST',{clean_ip:c.value,ip_pool:p.value,proxy_ip:x.value});await load();toast('ذخیره شد');})},'ذخیره'));}

function setView(){const s=S.settings;
 const en=el('input',{type:'checkbox',style:'width:auto'});en.checked=s.frag_enabled==='1';
 const pk=el('input',{value:s.frag_packets,style:'direction:ltr'}),ln=el('input',{value:s.frag_length,style:'direction:ltr'}),iv=el('input',{value:s.frag_interval,style:'direction:ltr'}),pf=el('input',{value:s.prefix});
 return el('div',{class:'card'},el('h3',{},'فرگمنت (Fragment)'),
  el('div',{class:'mut'},'فقط در خروجی JSON اشتراک (v2rayNG و کلاینت‌های Xray) اعمال می‌شود؛ در Hiddify فرگمنت را از تنظیمات خود برنامه روشن کنید.'),
  el('label',{},el('span',{},'فعال '),en),el('label',{},'Packets'),pk,el('label',{},'Length'),ln,el('label',{},'Interval (ms)'),iv,
  el('label',{},'پیشوند نام کانفیگ‌ها'),pf,
  el('button',{class:'pri',style:'margin-top:14px;width:100%',onclick:()=>run(async()=>{await api('/settings','POST',{frag_enabled:en.checked,frag_packets:pk.value,frag_length:ln.value,frag_interval:iv.value,prefix:pf.value});await load();toast('ذخیره شد');})},'ذخیره'));}
load();
</script></body></html>`;
