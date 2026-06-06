const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { sanitizeText, sanitizeHtml, validateEmail, validateName, validateMessage } = require('../utils/sanitize');
const { contactLimiter } = require('../middleware/rateLimiter');
const logger = require('../utils/logger');

let indexTemplate = null;
function getIndexTemplate() {
  if (indexTemplate) return indexTemplate;
  indexTemplate = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');
  return indexTemplate;
}

const sectionRoutes = ['/', '/about', '/projects', '/contact'];

sectionRoutes.forEach((route) => {
  router.get(route, (req, res) => {
    try {
      let html = getIndexTemplate();
      const token = req.session.csrfToken || '';
      html = html.replace('{{csrfToken}}', token);
      res.send(html);
    } catch (err) {
      logger.error('Error serving page', { error: err.message });
      res.status(500).sendFile(path.join(__dirname, '..', 'public', '500.html'));
    }
  });
});

router.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime(), timestamp: Date.now() });
});

router.post('/api/contact', contactLimiter, (req, res) => {
  try {
    const token = req.session.csrfToken;
    const submittedToken = req.body._csrf;

    if (!token || !submittedToken || token !== submittedToken) {
      return res.status(403).json({ error: 'Invalid CSRF token. Please refresh the page.' });
    }

    const name = sanitizeHtml(sanitizeText(req.body.name || ''));
    const email = sanitizeHtml(sanitizeText(req.body.email || ''));
    const message = sanitizeHtml(sanitizeText(req.body.message || ''));

    const errors = [];
    if (!validateName(name)) errors.push('name');
    if (!validateEmail(email)) errors.push('email');
    if (!validateMessage(message)) errors.push('message');

    if (errors.length > 0) {
      return res.status(422).json({ error: 'Validation failed', fields: errors });
    }

    logger.info('Contact form submission', {
      name, email, messageLength: message.length, ip: req.ip,
    });

    return res.json({
      success: true,
      message: 'Thank you! Your message has been received.',
    });
  } catch (err) {
    logger.error('Contact form error', { error: err.message });
    return res.status(500).json({ error: 'An unexpected error occurred.' });
  }
});

router.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '..', 'public', '404.html'));
});

module.exports = router;
