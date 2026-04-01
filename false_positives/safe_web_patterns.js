/**
 * False positive test cases for JavaScript/TypeScript web security.
 * All functions here are SAFE despite matching vulnerability patterns.
 */

const DOMPurify = require("dompurify");
const { JSDOM } = require("jsdom");
const crypto = require("crypto");

// --- XSS False Positives ---

function renderUserContent(userHtml) {
  /** DOMPurify-sanitized content set via innerHTML - SAFE. */
  const clean = DOMPurify.sanitize(userHtml, { ALLOWED_TAGS: ["b", "i", "p"] });
  document.getElementById("content").innerHTML = clean;
}

function displayNotification(message) {
  /** textContent used instead of innerHTML - SAFE. */
  const el = document.createElement("div");
  el.textContent = message;
  document.getElementById("notifications").appendChild(el);
}

function renderMarkdown(mdText) {
  /** Markdown rendered then sanitized before DOM insertion - SAFE. */
  const marked = require("marked");
  const rawHtml = marked.parse(mdText);
  const sanitized = DOMPurify.sanitize(rawHtml);
  document.getElementById("preview").innerHTML = sanitized;
}

function setDataAttribute(el, key, value) {
  /** setAttribute on data- attributes (not event handlers) - SAFE. */
  if (!key.startsWith("data-")) {
    throw new Error("Only data attributes allowed");
  }
  el.setAttribute(key, value);
}


// --- SQL Injection False Positives ---

async function getUserById(pool, userId) {
  /** Parameterized query - NOT SQL injection. */
  const result = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);
  return result.rows[0];
}

async function searchProducts(db, searchTerm) {
  /** Parameterized LIKE query - NOT injection. */
  const stmt = db.prepare("SELECT * FROM products WHERE name LIKE ?");
  return stmt.all(`%${searchTerm}%`);
}

async function insertUser(knex, userData) {
  /** Knex query builder (parameterized internally) - NOT injection. */
  return knex("users").insert({
    name: userData.name,
    email: userData.email,
  });
}

async function prismaQuery(prisma, email) {
  /** Prisma ORM query - NOT injection. */
  return prisma.user.findUnique({ where: { email } });
}


// --- Command Injection False Positives ---

function getNodeVersion() {
  /** Hardcoded command with no user input - SAFE. */
  const { execSync } = require("child_process");
  return execSync("node --version").toString().trim();
}

function resizeImage(width, height) {
  /** Numeric-only parameters, no shell - SAFE. */
  const { execFileSync } = require("child_process");
  const w = parseInt(width, 10);
  const h = parseInt(height, 10);
  if (isNaN(w) || isNaN(h) || w > 4096 || h > 4096) {
    throw new Error("Invalid dimensions");
  }
  return execFileSync("convert", [
    "input.png",
    "-resize",
    `${w}x${h}`,
    "output.png",
  ]);
}


// --- API Key / Secret False Positives ---

function createOpenAIClient() {
  /** API key from environment variable - NOT hardcoded. */
  const OpenAI = require("openai");
  return new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
}

function createAnthropicClient() {
  /** API key from config service - NOT hardcoded. */
  const Anthropic = require("@anthropic-ai/sdk");
  const apiKey = getSecretFromVault("anthropic-api-key");
  return new Anthropic({ apiKey });
}

function getSecretFromVault(name) {
  /** Simulated vault lookup - SAFE. */
  return process.env[name.toUpperCase().replace(/-/g, "_")];
}


// --- Crypto False Positives ---

function generateCacheKey(url) {
  /** MD5 for cache key (non-security use) - acceptable. */
  return crypto.createHash("md5").update(url).digest("hex");
}

function generateSecureToken() {
  /** crypto.randomBytes for token generation - SAFE. */
  return crypto.randomBytes(32).toString("hex");
}

module.exports = {
  renderUserContent,
  getUserById,
  getNodeVersion,
  createOpenAIClient,
  generateSecureToken,
};
