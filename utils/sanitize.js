const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

function sanitizeText(input) {
  if (typeof input !== 'string') return '';
  return input
    .replace(/[\0\x08\x09\x1a\n\r"'\\%]/g, (char) => {
      const map = {
        '\0': '\\0', '\x08': '\\b', '\x09': '\\t', '\x1a': '\\z',
        '\n': '\\n', '\r': '\\r', '"': '', "'": '',
        '\\': '\\\\', '%': '',
      };
      return map[char] || char;
    })
    .trim();
}

function sanitizeHtml(input) {
  if (typeof input !== 'string') return '';
  return DOMPurify.sanitize(input, {
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: [],
  }).trim();
}

function validateEmail(email) {
  if (typeof email !== 'string') return false;
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email) && email.length <= 254;
}

function validateName(name) {
  if (typeof name !== 'string') return false;
  return name.length >= 2 && name.length <= 100;
}

function validateMessage(msg) {
  if (typeof msg !== 'string') return false;
  return msg.length >= 10 && msg.length <= 5000;
}

module.exports = {
  sanitizeText,
  sanitizeHtml,
  validateEmail,
  validateName,
  validateMessage,
};
