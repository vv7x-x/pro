const rateLimit = require('express-rate-limit');

const contactLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests. Please try again later.',
    code: 'RATE_LIMIT_EXCEEDED',
  },
  keyGenerator: (req) => {
    return req.ip || req.connection.remoteAddress;
  },
});

const generalLimiter = rateLimit({
  windowMs: 60000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests.',
    code: 'RATE_LIMIT_GENERAL',
  },
});

module.exports = { contactLimiter, generalLimiter };
