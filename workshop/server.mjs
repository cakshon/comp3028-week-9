import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import { fileURLToPath } from 'node:url';
import { UserService } from './user-service.mjs';

for (const key of ['SESSION_SECRET', 'JWT_SECRET']) {
  if (!process.env[key] || process.env[key].length < 32) {
    throw new Error(`${key} must contain at least 32 characters`);
  }
}
const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const cookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: 'strict',
  path: '/'
};
app.set('view engine', 'ejs');
app.set('views', fileURLToPath(new URL('./views/', import.meta.url)));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(session({
  name: 'workshop.sid',
  secret: process.env.SESSION_SECRET,
  saveUninitialized: false,
  resave: false,
  cookie: { ...cookieOptions, maxAge: 60000 }
}));
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});
app.get('/', (req, res) => {
  res.send('Workshop 9 ready. Visit /login or /loginjwt.');
});

app.get('/session-demo', (req, res) => {
  req.session.username = 'brad';
  req.session.visits = (req.session.visits || 0) + 1;
  res.json({
    username: req.session.username,
    visits: req.session.visits
  });
});

function createToken(req, res) {
  // A mock user: this route demonstrates token creation only.
  const user = { id: 1, username: 'brad' };
  const token = jwt.sign(
    { user }, process.env.JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '2m' }
  );
  res.cookie('token', token, cookieOptions);
  res.send('Token created. Now visit /check-token.');
}
function checkToken(req, res) {
  try {
    if (!req.cookies.token) throw new Error('No token');
    const decoded = jwt.verify(
      req.cookies.token, process.env.JWT_SECRET,
      { algorithms: ['HS256'] }
    );
    if (!decoded.user?.username) throw new Error('Wrong payload');
    req.user = decoded.user;
    res.send(`Token is valid. User: ${req.user.username}`);
  } catch {
    res.status(401).send('Unauthorised access');
  }
}
app.post('/create-token', createToken);
app.get('/check-token', checkToken);

app.get('/login', (req, res) => {
  res.render('login', {
    title: 'Session login', action: '/login', message: ''
  });
});
app.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body || {};
    const user = await new UserService()
      .validUserCredentials(username, password);
    if (!user) {
      return req.session.destroy(err => {
        if (err) return next(err);
        res.clearCookie('workshop.sid', cookieOptions);
        return res.status(401).render('login', {
          title: 'Session login', action: '/login',
          message: 'Invalid username or password'
        });
      });
    }
    // Issue a new session ID after successful authentication.
    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.user = {
        id: user.id, username: user.username, role: user.role
      };
      req.session.save(err => {
        if (err) return next(err);
        return res.redirect(302, '/dashboard');
      });
    });
  } catch (err) {
    next(err);
  }
});
function authoriseSession(roles) {
  return (req, res, next) => {
    const user = req.session.user;
    if (!user) return res.redirect(302, '/login');
    if (!roles.includes(user.role)) {
      return res.status(403).send('Forbidden: role not allowed');
    }
    next();
  };
}
app.get('/dashboard', authoriseSession(['student', 'admin']),
  (req, res) => res.json({
    message: 'Session dashboard', user: req.session.user
  })
);
app.get('/admin', authoriseSession(['admin']),
  (req, res) => res.send('Session admin area')
);
app.post('/logout', (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie('workshop.sid', cookieOptions);
    res.redirect(302, '/login');
  });
});

app.get('/loginjwt', (req, res) => {
  res.render('login', {
    title: 'JWT login', action: '/loginjwt', message: ''
  });
});
app.post('/loginjwt', async (req, res, next) => {
  try {
    const { username, password } = req.body || {};
    const user = await new UserService()
      .validUserCredentials(username, password);
    if (!user) {
      res.clearCookie('token', cookieOptions);
      return res.status(401).render('login', {
        title: 'JWT login', action: '/loginjwt',
        message: 'Invalid username or password'
      });
    }
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '3m' }
    );
    res.cookie('token', token, {
      ...cookieOptions, maxAge: 180000
    });
    res.redirect(302, '/dashboardjwt');
  } catch (err) {
    next(err);
  }
});
function authoriseJWT(roles) {
  return (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect(302, '/loginjwt');
    let user;
    try {
      user = jwt.verify(token, process.env.JWT_SECRET, {
        algorithms: ['HS256']
      });
    } catch {
      res.clearCookie('token', cookieOptions);
      return res.redirect(302, '/loginjwt');
    }
    if (!roles.includes(user.role)) {
      return res.status(403).send('Forbidden: role not allowed');
    }
    req.user = user;
    next();
  };
}
app.get('/dashboardjwt', authoriseJWT(['student', 'admin']),
  (req, res) => res.json({
    message: 'JWT dashboard', user: req.user
  })
);
app.get('/adminjwt', authoriseJWT(['admin']),
  (req, res) => res.send('JWT admin area')
);
app.post('/logoutjwt', (req, res) => {
  res.clearCookie('token', cookieOptions);
  res.redirect(302, '/loginjwt');
});

app.use((err, req, res, next) => {
  console.error(err.message);
  res.status(500).send('Server error. Check the terminal.');
});
const port = Number(process.env.PORT || 3000);
app.listen(port, '127.0.0.1', () => {
  console.log(`Workshop running at http://localhost:${port}`);
});
