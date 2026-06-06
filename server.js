require('dotenv').config();
const express = require('express');
const session = require('express-session');
const compression = require('compression');
const path = require('path');
const crypto = require('crypto');
const { nonceMiddleware, helmetMiddleware, additionalHeaders } = require('./middleware/security');
const { generalLimiter } = require('./middleware/rateLimiter');
const webRoutes = require('./routes/web');
const logger = require('./utils/logger');

const app = express();
const PORT = process.env.PORT || 3000;

if (process.env.TRUST_PROXY === '1') {
  app.set('trust proxy', 1);
}

app.use(compression());
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: '10kb' }));

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  name: 'sid',
  cookie: {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === 'true',
    sameSite: 'strict',
    maxAge: parseInt(process.env.SESSION_MAX_AGE, 10) || 86400000,
  },
}));

app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
});

app.use(nonceMiddleware);
app.use(helmetMiddleware);
app.use(additionalHeaders);
app.use(generalLimiter);

app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '7d' : 0,
  etag: true,
  index: false,
}));

app.use('/', webRoutes);

app.use((err, req, res, next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack });
  if (res.headersSent) return;
  res.status(500).sendFile(path.join(__dirname, 'public', '500.html'));
});

process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled rejection', { reason: String(reason) });
});

app.listen(PORT, () => {
  logger.info(`Server started on port ${PORT}`);
  console.log(`Server running on http://localhost:${PORT}`);
});
