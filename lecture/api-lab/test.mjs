// Start server.mjs in another terminal before running this check.
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
const base = 'http://127.0.0.1:3000';
let passed = 0;
async function request(path, status, { method = 'GET', body, token, cookie } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(base + path, { method, headers,
    body: body === undefined ? undefined : JSON.stringify(body) });
  const raw = await res.text();
  assert.equal(res.status, status, `${method} ${path}: ${raw}`);
  passed++;
  return { data: raw ? JSON.parse(raw) : null, headers: res.headers };
}
const alice = { username: 'alice', password: 'AliceDemo!42' };
const bob = { username: 'bob', password: 'BobDemo!42' };
await request('/health', 200);
await request('/session/me', 401);
const login = await request('/session/login', 200, { method: 'POST', body: alice });
const cookie = login.headers.get('set-cookie').split(';')[0];
assert.match(login.headers.get('set-cookie'), /HttpOnly/i);
assert.match(login.headers.get('set-cookie'), /SameSite=Strict/i);
await request('/session/me', 200, { cookie });
await request('/session/logout', 204, { method: 'POST', cookie });
await request('/session/me', 401, { cookie }); // Replay the old cookie.
await request('/jwt/login', 401, { method: 'POST', body: { ...alice, password: 'wrong' } });
await request('/jwt/login', 400, { method: 'POST', body: { ...alice, password: 123 } });
await request('/jwt/login', 400, { method: 'POST', body: { ...alice, password: 'x'.repeat(73) } });
const a = (await request('/jwt/login', 200, { method: 'POST', body: alice })).data.accessToken;
const b = (await request('/jwt/login', 200, { method: 'POST', body: bob })).data.accessToken;
await request('/jwt/me', 401);
const profile = await request('/jwt/me', 200, { token: a });
assert.equal(profile.data.user.id, 'u1');
assert.equal('passwordHash' in profile.data.user, false);
const parts = a.split('.');
parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
await request('/jwt/me', 401, { token: parts.join('.') });
await request('/jwt/admin', 403, { token: a });
await request('/jwt/admin', 200, { token: b });
await request('/jwt/notes/n1', 200, { token: a });
await request('/jwt/notes/n2', 404, { token: a });
await request('/jwt/notes/n2', 200, { token: b });
await request('/jwt/notes/n1', 404, { token: b });
await request('/jwt/notes', 403, { method: 'POST', token: a, body: { text: 'Test' } });
await request('/jwt/notes', 400, { method: 'POST', token: b, body: { text: '' } });
await request('/jwt/notes', 400, { method: 'POST', token: b, body: { text: 42 } });
const created = await request('/jwt/notes', 201, { method: 'POST', token: b, body: { text: 'Test' } });
assert.equal(created.data.note.ownerId, 'u2');
// Isolated library check, not an endpoint expiry test.
const expired = jwt.sign({}, 'test-only-secret', { expiresIn: -1 });
assert.throws(() => jwt.verify(expired, 'test-only-secret'), { name: 'TokenExpiredError' });
console.log(`${passed} HTTP checks passed; passwordHash excluded; expired-token library check passed.`);
