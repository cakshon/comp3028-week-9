// Local teaching demo. Do not deploy this in-memory example.
import express from 'express';
import session from 'express-session';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { randomBytes } from 'node:crypto';

const app = express();
app.use(express.json({ limit: '10kb' }));
const sessionSecret = randomBytes(32).toString('hex');
const jwtSecret = randomBytes(32).toString('hex');
app.use(session({
  name: 'lab.sid', secret: sessionSecret,
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict',
    secure: false, maxAge: 15 * 60 * 1000 }
})); // secure:false is for localhost HTTP only.

const users = [
  { id: 'u1', username: 'alice', role: 'student',
    permissions: ['notes:read'],
    passwordHash: await bcrypt.hash('AliceDemo!42', 10) },
  { id: 'u2', username: 'bob', role: 'admin',
    permissions: ['notes:read', 'notes:write'],
    passwordHash: await bcrypt.hash('BobDemo!42', 10) }
];
const notes = [
  { id: 'n1', ownerId: 'u1', text: 'Alice private note' },
  { id: 'n2', ownerId: 'u2', text: 'Bob private note' }
];
const publicUser = u => ({ id: u.id, username: u.username,
  role: u.role, permissions: u.permissions });
app.get('/health', (req, res) => res.json({ status: 'ok' }));

async function checkCredentials(req, res, next) {
  const { username, password } = req.body ?? {};
  if (typeof username !== 'string' ||
      typeof password !== 'string' ||
      username.length < 1 || username.length > 40 ||
      password.length < 1 ||
      Buffer.byteLength(password, 'utf8') > 72) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  const user = users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  req.user = user;
  next();
}

app.post('/session/login', checkCredentials, (req, res, next) => {
  req.session.regenerate(err => {
    if (err) return next(err);
    req.session.userId = req.user.id;
    req.session.save(err => {
      if (err) return next(err);
      res.json({ user: publicUser(req.user) });
    });
  });
});
function requireSession(req, res, next) {
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: 'Login required' });
  req.user = user;
  next();
}
app.get('/session/me', requireSession, (req, res) => {
  res.json({ user: publicUser(req.user) });
});
app.post('/session/logout', (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie('lab.sid', { path: '/' });
    res.status(204).end();
  });
});

const tokenOptions = { algorithm: 'HS256', expiresIn: '1s',
  issuer: 'comp3028-lab', audience: 'comp3028-client' };
app.post('/jwt/login', checkCredentials, (req, res) => {
  const accessToken = jwt.sign({}, jwtSecret, {
    ...tokenOptions, subject: req.user.id
  });
  res.json({ accessToken, tokenType: 'Bearer', expiresIn: 1 });
});
function requireJwt(req, res, next) {
  const match = /^Bearer (\S+)$/.exec(req.get('Authorization') ?? '');
  if (!match) return res.status(401).json({ error: 'Bearer token required' });
  try {
    const claims = jwt.verify(match[1], jwtSecret, {
      algorithms: ['HS256'], issuer: tokenOptions.issuer,
      audience: tokenOptions.audience
    });
    const user = users.find(u => u.id === claims.sub);
    if (!user) return res.status(401).json({ error: 'Unknown user' });
    req.user = user;
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  next();
}
app.get('/jwt/me', requireJwt, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role)
      return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user.permissions.includes(permission))
      return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}
app.get('/jwt/admin', requireJwt, requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin access granted' });
});
app.get('/jwt/notes/:id', requireJwt,
  requirePermission('notes:read'), (req, res) => {
    const note = notes.find(n => n.id === req.params.id);
    if (!note || note.ownerId !== req.user.id)
      return res.status(404).json({ error: 'Note not found' });
    res.json({ note });
  });
app.post('/jwt/notes', requireJwt,
  requirePermission('notes:write'), (req, res) => {
    const text = req.body?.text;
    if (typeof text !== 'string' || !text.trim() || text.length > 200)
      return res.status(400).json({ error: 'Text must be 1-200 characters' });
    const note = { id: `n${notes.length + 1}`,
      ownerId: req.user.id, text: text.trim() };
    notes.push(note);
    res.status(201).json({ note });
  });
app.use((err, req, res, next) => {
  const status = err.status === 400 ? 400 : err.status === 413 ? 413 : 500;
  res.status(status).json({ error: status === 500 ? 'Server error' : 'Invalid request' });
});
app.listen(3000, '127.0.0.1', () => {
  console.log('API ready at http://127.0.0.1:3000');
});
