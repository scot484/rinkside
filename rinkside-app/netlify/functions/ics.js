// RinkSide schedule sync: fetches a TeamSnap calendar feed server-side (no CORS limits)
// Only TeamSnap calendar hosts are allowed, so this can't be abused as an open proxy.
const ALLOWED_HOSTS = ['ical-cdn.teamsnap.com', 'ical.teamsnap.com', 'go.teamsnap.com'];

exports.handler = async function(event) {
  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: cors, body: '' };

  let raw = (event.queryStringParameters && event.queryStringParameters.url) || '';
  raw = raw.replace(/^webcal:\/\//i, 'https://');
  let url;
  try { url = new URL(raw); } catch (e) {
    return { statusCode: 400, headers: cors, body: 'Invalid url' };
  }
  if (!ALLOWED_HOSTS.includes(url.hostname)) {
    return { statusCode: 403, headers: cors, body: 'Only TeamSnap calendar links are allowed' };
  }
  try {
    const res = await fetch(url.toString(), { redirect: 'follow' });
    if (!res.ok) return { statusCode: 502, headers: cors, body: 'Upstream error ' + res.status };
    const text = await res.text();
    return {
      statusCode: 200,
      headers: { ...cors, 'Content-Type': 'text/calendar; charset=utf-8', 'Cache-Control': 'no-store' },
      body: text
    };
  } catch (e) {
    return { statusCode: 502, headers: cors, body: 'Fetch failed: ' + (e.message || e) };
  }
};
