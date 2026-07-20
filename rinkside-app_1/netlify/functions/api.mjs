// RinkSide accounts + cross-device sync, backed by Netlify Blobs.
// Works with the @netlify/blobs package when installed, and falls back to
// the Blobs HTTP API using the runtime-injected NETLIFY_BLOBS_CONTEXT.
import crypto from 'node:crypto';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type'
};
const resp = (code, obj) => ({ statusCode: code, headers: { ...CORS, 'Content-Type': 'application/json' }, body: JSON.stringify(obj) });

function hashPassword(password, salt){
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

/* ---- storage layer ----
   Preferred: @netlify/blobs getStore(), manually configured with the
   token + siteID from our own env vars. This is the documented way to
   use Blobs outside the auto-configured build environment, so it does
   not depend on Netlify's build step running (which Drop deploys skip). */
async function makeStore(){
  let mod;
  try{
    mod = await import('@netlify/blobs');
  }catch(e){
    throw new Error('Storage not configured: the @netlify/blobs package is missing from this deploy. Redeploy with the build step enabled, or ensure the package.json in the deploy folder includes @netlify/blobs.');
  }
  const token = process.env.NETLIFY_API_TOKEN;
  const siteID = process.env.NETLIFY_SITE_ID || process.env.SITE_ID;

  let s, mode;
  if (token && siteID) {
    s = mod.getStore({ name: 'rinkside', token, siteID });
    mode = 'manual-config';
  } else {
    try{
      s = mod.getStore('rinkside');
      mode = 'auto-context';
    }catch(e){
      throw new Error('Storage not configured. In Netlify: create a Personal Access Token (user settings), then add site environment variables NETLIFY_API_TOKEN and NETLIFY_SITE_ID, then redeploy.');
    }
  }
  return {
    mode,
    get: (k) => s.get(k, { type: 'json' }),
    set: (k, obj) => s.setJSON(k, obj),
    del: (k) => s.delete(k)
  };
}

export const handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS, body: '' };
  if (event.httpMethod !== 'POST') return resp(405, { error: 'POST only' });
  try{
    let body;
    try { body = JSON.parse(event.body || '{}'); } catch { return resp(400, { error: 'Bad JSON' }); }
    const store = await makeStore();
    const action = body.action;

    const uname = (body.username || '').trim().toLowerCase();
    const unameOk = /^[a-z0-9_.-]{3,30}$/.test(uname);

    if (action === 'ping') return resp(200, { ok: true, storage: store.mode });

    if (action === 'register' || action === 'login') {
      const password = body.password || '';
      if (!unameOk) return resp(400, { error: 'Username must be 3-30 characters: letters, numbers, dots, dashes.' });
      if (password.length < 6) return resp(400, { error: 'Password must be at least 6 characters.' });

      const userKey = 'user:' + uname;
      const existing = await store.get(userKey);

      if (action === 'register') {
        if (existing) return resp(409, { error: 'That username is taken.' });
        const salt = crypto.randomBytes(16).toString('hex');
        await store.set(userKey, { salt, hash: hashPassword(password, salt), created: Date.now() });
      } else {
        if (!existing) return resp(401, { error: 'No account with that username.' });
        const tryHash = hashPassword(password, existing.salt);
        const a = Buffer.from(tryHash); const b = Buffer.from(existing.hash);
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return resp(401, { error: 'Wrong password.' });
      }
      const token = crypto.randomBytes(32).toString('hex');
      await store.set('session:' + token, { username: uname, created: Date.now() });
      return resp(200, { token, username: uname });
    }

    const token = body.token || '';
    if (!token) return resp(401, { error: 'Not signed in.' });
    const session = await store.get('session:' + token);
    if (!session) return resp(401, { error: 'Session expired — sign in again.' });
    const dataKey = 'data:' + session.username;

    if (action === 'pull') {
      const data = await store.get(dataKey);
      return resp(200, { data: data || null, username: session.username });
    }
    if (action === 'push') {
      if (typeof body.data !== 'object' || body.data === null) return resp(400, { error: 'No data.' });
      if (JSON.stringify(body.data).length > 4_500_000) return resp(413, { error: 'Data too large.' });
      await store.set(dataKey, body.data);
      return resp(200, { ok: true, savedAt: Date.now() });
    }
    if (action === 'logout') {
      await store.del('session:' + token);
      return resp(200, { ok: true });
    }
    return resp(400, { error: 'Unknown action.' });
  }catch(e){
    return resp(500, { error: 'Server error: ' + (e && e.message ? e.message : String(e)) });
  }
};
