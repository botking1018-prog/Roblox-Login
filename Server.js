import express from 'express';
import cors from 'cors';

const app = express();

/* ============================================================
   1. CORS  –  MUSS vor allen Routen stehen
   ============================================================ */
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
}));

app.use(express.json());

/* ============================================================
   2. Einstellungen
   ============================================================ */
const KEY = process.env.CAPTCHA_KEY || '69d7ba6633b6005d2dbb64dfb4257b44';
const ARKOSE_KEYS = [
  '476068BF-9607-4799-B53D-966BE98E2B81',
  '9F35E182-C93C-EBCC-A31D-CF8ED317B996'
];
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

const LOGIN_URL = 'https://auth.roblox.com/v2/login';
const TWOFA_URL = 'https://auth.roblox.com/v2/twostepverification/verify';

const sessions = new Map();

/* ============================================================
   3. Cookie-Topf
   ============================================================ */
function setCookieLines(res) {
  const h = res.headers;

  // Normalfall (Node 20+)
  if (typeof h.getSetCookie === 'function') {
    const list = h.getSetCookie();
    if (list && list.length) return list;
  }

  // Ersatz für Node 18
  const joined = h.get('set-cookie');
  if (!joined) return [];
  return joined.split(/,(?=\s*[^;=,\s]+=)/);
}

class Jar {
  constructor() {
    this.map = new Map();
  }
  add(res) {
    for (const line of setCookieLines(res)) {
      const pair = line.split(';')[0];
      const i = pair.indexOf('=');
      if (i > 0) this.map.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
    }
  }
  header() {
    return [...this.map.entries()].map(([k, v]) => k + '=' + v).join('; ');
  }
  get(name) {
    return this.map.get(name) || null;
  }
}

/* ============================================================
   4. Hilfsfunktionen für Roblox
   ============================================================ */
function rbx(url, body, { jar, csrf = '', extra = {}, withOrigin = false } = {}) {
  const h = {
    'Content-Type': 'application/json',
    'User-Agent': UA,
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.9'
  };
  if (withOrigin) {
    h['Origin'] = 'https://www.roblox.com';
    h['Referer'] = 'https://www.roblox.com/';
  }
  if (jar && jar.header()) h['Cookie'] = jar.header();
  if (csrf) h['x-csrf-token'] = csrf;
  Object.assign(h, extra);

  return fetch(url, { method: 'POST', headers: h, body: JSON.stringify(body) });
}

async function readJson(res) {
  const text = await res.text();
  try { return JSON.parse(text); } catch { return {}; }
}

async function getCsrf(jar) {
  const headers = { 'User-Agent': UA };
  if (jar.header()) headers['Cookie'] = jar.header();

  const r = await fetch('https://auth.roblox.com/v2/logout', { method: 'POST', headers });
  jar.add(r);
  return r.headers.get('x-csrf-token') || jar.get('XSRF-TOKEN') || '';
}

/* ============================================================
   5. 2captcha
   ============================================================ */
async function solveArkose(publicKey, blob) {
  const task = {
    type: 'FunCaptchaTaskProxyless',
    websiteURL: 'https://www.roblox.com/login',
    websitePublicKey: publicKey,
    surl: 'https://roblox-api.arkoselabs.com'
  };
  if (blob) task.data = blob;

  const created = await fetch('https://api.2captcha.com/createTask', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ clientKey: KEY, task })
  }).then(r => r.json());

  if (created.errorId) throw new Error(created.errorDescription || created.errorCode);

  for (let i = 0; i < 60; i++) {
    await new Promise(r => setTimeout(r, 2000));
    const res = await fetch('https://api.2captcha.com/getTaskResult', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientKey: KEY, taskId: created.taskId })
    }).then(r => r.json());

    if (res.status === 'ready') return res.solution.token;
    if (res.errorId) throw new Error(res.errorDescription || res.errorCode);
  }
  throw new Error('Captcha-Timeout');
}

/* ============================================================
   6. Routen
   ============================================================ */
app.get('/', (req, res) => {
  res.json({ ok: true, routes: ['/health', '/balance', '/login', '/verify2fa'] });
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.get('/balance', async (req, res) => {
  try {
    const d = await fetch('https://api.2captcha.com/getBalance', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientKey: KEY })
    }).then(r => r.json());
    res.json(d);
  } catch (e) {
    res.json({ error: e.message });
  }
});

/* ---------- Login ---------- */
app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.json({ error: { errors: [{ message: 'Felder leer' }] } });
  }

  const jar = new Jar();
  const creds = { ctype: 'Username', cvalue: username, password };

  try {
    // Schritt A: CSRF-Token holen
    let csrf = await getCsrf(jar);

    // Schritt B: Login-Versuch
    let r = await rbx(LOGIN_URL, creds, { jar, csrf, withOrigin: true });
    jar.add(r);
    let data = await readJson(r);

    // Schritt C: CSRF hat noch gefehlt -> einmal mit Token wiederholen
    if (r.status === 403 && !r.headers.get('rblx-challenge-type') && !data.twoStepVerificationData) {
      csrf = r.headers.get('x-csrf-token') || csrf;
      r = await rbx(LOGIN_URL, creds, { jar, csrf, withOrigin: true });
      jar.add(r);
      data = await readJson(r);
    }

    // Schritt D: Captcha verlangt
    if (r.status === 403 && r.headers.get('rblx-challenge-type')) {
      let key = ARKOSE_KEYS[0];
      let blob = null;

      const meta = r.headers.get('rblx-challenge-metadata');
      if (meta) {
        try {
          const m = JSON.parse(Buffer.from(meta, 'base64').toString());
          const cm = typeof m.challengeMetadata === 'string'
            ? JSON.parse(m.challengeMetadata)
            : m.challengeMetadata;
          if (cm && cm.publicKey) key = cm.publicKey;
          if (cm && cm.blob) blob = cm.blob;
        } catch {}
      }

      const token = await solveArkose(key, blob);
      const challengeId = r.headers.get('rblx-challenge-id');
      const extra = challengeId ? { 'rblx-challenge-id': challengeId } : {};

      r = await rbx(LOGIN_URL, {
        ...creds,
        captchaToken: token,
        captchaProvider: 'PROVIDER_ARKOSE_LABS'
      }, { jar, csrf, withOrigin: true, extra });

      jar.add(r);
      data = await readJson(r);
    }

    // Schritt E: 2FA verlangt
    if (data.twoStepVerificationData) {
      const t = data.twoStepVerificationData;
      sessions.set(t.ticket, { jar });
      return res.json({ needs2FA: true, ticket: t.ticket, mediaType: t.mediaType });
    }

    // Schritt F: Erfolg
    const cookie = jar.get('.ROBLOSECURITY');
    if (cookie) return res.json({ success: true, cookie });

    return res.json({ error: data });

  } catch (e) {
    res.json({ error: { errors: [{ message: e.message }] } });
  }
});

/* ---------- 2FA-Code prüfen ---------- */
app.post('/verify2fa', async (req, res) => {
  const { ticket, code } = req.body || {};
  const sess = sessions.get(ticket);

  if (!sess) {
    return res.json({ error: { errors: [{ message: 'Session abgelaufen' }] } });
  }

  try {
    const csrf = await getCsrf(sess.jar);
    const r = await rbx(TWOFA_URL, { ticket, code, rememberDevice: false }, { jar: sess.jar, csrf });
    sess.jar.add(r);
    const data = await readJson(r);

    const cookie = sess.jar.get('.ROBLOSECURITY');
    if (cookie) {
      sessions.delete(ticket);
      return res.json({ success: true, cookie });
    }
    return res.json({ error: data });

  } catch (e) {
    res.json({ error: { errors: [{ message: e.message }] } });
  }
});

/* ============================================================
   7. Start
   ============================================================ */
const PORT = process.env.PORT || 3000;
