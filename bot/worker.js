// Nuroia Panel - Telegram bot (Cloudflare Worker, webhook)
// Secrets: BOT_TOKEN, WEBHOOK_SECRET   Vars: see wrangler.toml
// هیچ دیتابیسی ندارد: عضویت از تلگرام چک می‌شود و توکن فقط یک‌بار استفاده و ذخیره نمی‌شود.

const CF = 'https://api.cloudflare.com/client/v4';
const TOKEN_LINK = 'https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%5D&accountId=*&zoneId=all&name=NuroiaPanel';
const TOKEN_RE = /^[A-Za-z0-9_-]{40}$/;

const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
const rand = (n, chars = 'abcdefghijklmnopqrstuvwxyz0123456789') =>
  [...crypto.getRandomValues(new Uint8Array(n))].map((x) => chars[x % chars.length]).join('');

async function tg(env, method, body) {
  const r = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return r.json();
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    // ثبت وبهوک:  /setup?key=<WEBHOOK_SECRET>
    if (url.pathname === '/setup' && url.searchParams.get('key') === env.WEBHOOK_SECRET) {
      const r = await tg(env, 'setWebhook', {
        url: `${url.origin}/webhook`,
        secret_token: env.WEBHOOK_SECRET,
        allowed_updates: ['message', 'callback_query'],
        drop_pending_updates: true,
      });
      return Response.json(r);
    }
    if (url.pathname !== '/webhook' || req.method !== 'POST') return new Response('Nuroia Bot');
    if (req.headers.get('x-telegram-bot-api-secret-token') !== env.WEBHOOK_SECRET)
      return new Response('forbidden', { status: 403 });
    const update = await req.json();
    ctx.waitUntil(handle(update, env).catch((e) => console.log('err', e && e.message)));
    return new Response('ok');
  },
};

async function isMember(env, chat, uid) {
  const r = await tg(env, 'getChatMember', { chat_id: chat, user_id: uid });
  if (!r.ok) { console.log('getChatMember failed', chat, r.description); return false; }
  const s = r.result.status;
  return ['creator', 'administrator', 'member'].includes(s) || (s === 'restricted' && r.result.is_member);
}
const joined = async (env, uid) =>
  (await isMember(env, env.CHANNEL_ID, uid)) && (await isMember(env, env.GROUP_ID, uid));

const sendJoin = (env, chat) =>
  tg(env, 'sendMessage', {
    parse_mode: 'HTML',
    text: '👋 به <b>Nuroia Panel</b> خوش آمدید.\n\nبرای استفاده از ربات ابتدا در کانال و گپ زیر عضو شوید و سپس دکمه «بررسی عضویت» را بزنید.',
    reply_markup: {
      inline_keyboard: [
        [{ text: '📢 عضویت در کانال', url: env.CHANNEL_URL }],
        [{ text: '💬 عضویت در گپ', url: env.GROUP_URL }],
        [{ text: '✅ بررسی عضویت', callback_data: 'chk' }],
      ],
    },
  });

const askToken = (env, chat) =>
  tg(env, 'sendMessage', {
    chat_id: chat,
    parse_mode: 'HTML',
    text:
      '✅ عضویت تایید شد.\n\nبرای ساخت پنل روی اکانت <b>کلودفلر خودتان</b> یک توکن لازم است:\n\n' +
      '۱) دکمه زیر را بزنید (اگر اکانت ندارید رایگان بسازید)\n' +
      '۲) «Continue to summary» و بعد «Create Token»\n' +
      '۳) توکن ساخته‌شده (۴۰ کاراکتر) را همین‌جا بفرستید\n\n' +
      '🔒 پیام توکن بلافاصله پاک می‌شود و جایی ذخیره نمی‌شود. بعد از ساخت پنل، توکن را از داشبورد کلودفلر حذف کنید.',
    reply_markup: { inline_keyboard: [[{ text: '🔑 ساخت توکن کلودفلر', url: TOKEN_LINK }]] },
  });

async function handle(u, env) {
  if (u.callback_query) {
    const q = u.callback_query;
    if (q.data !== 'chk') return;
    if (await joined(env, q.from.id)) {
      await tg(env, 'answerCallbackQuery', { callback_query_id: q.id, text: '✅ تایید شد' });
      await askToken(env, q.message.chat.id);
    } else {
      await tg(env, 'answerCallbackQuery', {
        callback_query_id: q.id, show_alert: true,
        text: '❌ هنوز در هر دو (کانال و گپ) عضو نشده‌اید.',
      });
    }
    return;
  }
  const m = u.message;
  if (!m || !m.text || m.chat.type !== 'private') return;
  const chat = m.chat.id;
  const text = m.text.trim();
  if (!(await joined(env, m.from.id))) return sendJoin(env, chat);
  const r = await fetch(CF + path, { ...opts, headers: { authorization: `Bearer ${token}`, ...(opts.headers || {}) } });
  const j = await r.json().catch(() => ({}));
  if (!j.success) throw new Error((j.errors && j.errors[0] && j.errors[0].message) || `Cloudflare ${r.status}`);
  return j.result;
}
const cfJson = (token, path, method, body) =>
  cf(token, path, { method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

async function build(env, chat, token) {
  const sent = await tg(env, 'sendMessage', { chat_id: chat, text: '⏳ در حال بررسی توکن…' });
  const mid = sent.result.message_id;
  const edit = (text) =>
    tg(env, 'editMessageText', { chat_id: chat, message_id: mid, text, parse_mode: 'HTML', disable_web_page_preview: true });
  let accountId, dbId;
  try {
    const v = await cf(token, '/user/tokens/verify');
    if (v.status !== 'active') throw new Error('توکن فعال نیست');
    const accounts = await cf(token, '/accounts');
    if (!accounts.length) throw new Error('اکانتی برای این توکن پیدا نشد (دسترسی Account Settings را چک کنید)');
    accountId = accounts[0].id;

    const src = await (await fetch(env.PANEL_SRC_URL)).text();
    if (!src.includes('NUROIA_PANEL')) throw new Error('سورس پنل از گیت‌هاب خوانده نشد');

    await edit('⏳ تنظیم دامنه workers.dev…');
    let sub;
    try { sub = (await cf(token, `/accounts/${accountId}/workers/subdomain`)).subdomain; } catch {}
    }

    await edit('⏳ ساخت دیتابیس D1…');
    const id = rand(6);
    const name = `nuroia-${id}`;
    const db = await cfJson(token, `/accounts/${accountId}/d1/database`, 'POST', { name });
    dbId = db.uuid;

    await edit('⏳ آپلود و راه‌اندازی پنل…');
    const password = rand(16, 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789');
    const metadata = {
      main_module: 'worker.js',
      compatibility_date: '2024-09-23',
      bindings: [
        { type: 'd1', name: 'DB', id: dbId },
        { type: 'secret_text', name: 'ADMIN_PASSWORD', text: password },
        { type: 'secret_text', name: 'SESSION_KEY', text: rand(48) },
      ],
    };
    const form = new FormData();
    form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
    form.append('worker.js', new Blob([src], { type: 'application/javascript+module' }), 'worker.js');
    await cf(token, `/accounts/${accountId}/workers/scripts/${name}`, { method: 'PUT', body: form });
    await cfJson(token, `/accounts/${accountId}/workers/scripts/${name}/subdomain`, 'POST', { enabled: true, previews_enabled: false });

    const url = `https://${name}.${sub}.workers.dev`;
    await edit(
      `✅ <b>پنل شما ساخته شد</b>\n\n🔗 آدرس: ${esc(url)}\n🔑 رمز ورود: <code>${password}</code>\n\n` +
      '• اگر لینک بلافاصله باز نشد، ۱ تا ۲ دقیقه صبر کنید.\n' +
      '• رمز را همین الان جایی ذخیره کنید؛ ما آن را نگه نمی‌داریم.\n' +
      '• توکن کلودفلر دیگر لازم نیست؛ از Profile ← API Tokens حذفش کنید.'
    );
    await tg(env, 'sendMessage', {
      chat_id: chat, text: 'ورود به پنل:',
      reply_markup: { inline_keyboard: [[{ text: '🚀 باز کردن پنل', url }]] },
    });
  } catch (e) {
    if (dbId) { try { await cf(token, `/accounts/${accountId}/d1/database/${dbId}`, { method: 'DELETE' }); } catch {} }
    await edit(`❌ ساخت پنل ناموفق بود:\n<code>${esc(e.message)}</code>\n\nدسترسی‌های توکن را (Workers Scripts:Edit ، D1:Edit ، Account Settings:Read) بررسی و دوباره توکن را بفرستید.`);
  }
}
