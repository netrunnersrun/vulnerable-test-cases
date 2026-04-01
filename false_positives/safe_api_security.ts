/**
 * False positive test cases for TypeScript API and LLM security.
 * All patterns here are SAFE despite resembling vulnerabilities.
 */

import { Request, Response } from "express";
import { createHash, randomBytes } from "crypto";

// --- Prompt Injection False Positives ---

interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

function buildSafePrompt(userQuestion: string): ChatMessage[] {
  /**
   * User input in a separate message (not concatenated into system prompt).
   * System message is hardcoded. This is the CORRECT pattern - NOT injection.
   */
  const systemPrompt =
    "You are a helpful assistant. Answer questions about our product.";
  return [
    { role: "system", content: systemPrompt },
    { role: "user", content: userQuestion },
  ];
}

async function chatWithValidation(client: any, userInput: string) {
  /**
   * User input validated and length-limited before LLM call - SAFE.
   * Despite using template literal, the input is sanitized.
   */
  const sanitized = userInput
    .replace(/[<>{}]/g, "")
    .slice(0, 500);

  const response = await client.chat.completions.create({
    model: "gpt-4",
    messages: [
      { role: "system", content: "Answer factual questions only." },
      { role: "user", content: sanitized },
    ],
    max_tokens: 150,
  });
  return response.choices[0].message.content;
}


// --- LLM Output Handling False Positives ---

async function getLLMSummary(client: any, text: string): Promise<string> {
  /**
   * LLM output returned but with content filtering applied - SAFE.
   * Output is sanitized before being returned to the user.
   */
  const response = await client.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: `Summarize: ${text}` }],
  });

  const output = response.choices[0].message.content;
  // Content filter applied before return
  const filtered = output
    .replace(/<script[^>]*>.*?<\/script>/gi, "")
    .replace(/javascript:/gi, "")
    .replace(/on\w+\s*=/gi, "");
  return filtered;
}

async function getLLMJsonResponse(client: any, query: string) {
  /**
   * LLM JSON output validated against schema before use - SAFE.
   */
  const response = await client.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: query }],
    response_format: { type: "json_object" },
  });

  const parsed = JSON.parse(response.choices[0].message.content);
  // Schema validation
  if (typeof parsed.answer !== "string" || parsed.answer.length > 1000) {
    throw new Error("Invalid LLM response format");
  }
  if (parsed.confidence !== undefined && typeof parsed.confidence !== "number") {
    throw new Error("Invalid confidence value");
  }
  return parsed;
}


// --- SSRF False Positives ---

async function fetchFromAllowedAPI(
  req: Request,
  res: Response
): Promise<void> {
  /**
   * URL validated against strict allowlist before fetch - NOT SSRF.
   */
  const targetUrl = req.query.url as string;
  const allowedOrigins = [
    "https://api.github.com",
    "https://registry.npmjs.org",
  ];

  const parsed = new URL(targetUrl);
  if (!allowedOrigins.some((origin) => targetUrl.startsWith(origin))) {
    res.status(403).json({ error: "Domain not allowed" });
    return;
  }
  if (parsed.protocol !== "https:") {
    res.status(403).json({ error: "HTTPS required" });
    return;
  }

  const response = await fetch(targetUrl);
  const data = await response.json();
  res.json(data);
}


// --- Error Handling False Positives ---

function handleExpressError(
  err: Error,
  req: Request,
  res: Response
): void {
  /**
   * Logs full error server-side, returns generic message to client - SAFE.
   * Error details never exposed to the user.
   */
  console.error("Unhandled error:", err.stack);
  const requestId = randomBytes(8).toString("hex");
  res.status(500).json({
    error: "Internal server error",
    requestId,
    message: "Please contact support with the request ID above.",
  });
}

function validateRequestBody(body: Record<string, unknown>): string[] {
  /**
   * Returns field-level validation errors (not stack traces) - SAFE.
   */
  const errors: string[] = [];
  if (!body.email || typeof body.email !== "string") {
    errors.push("Valid email is required");
  }
  if (!body.name || typeof body.name !== "string" || body.name.length > 100) {
    errors.push("Name is required (max 100 characters)");
  }
  return errors;
}


// --- Security Misconfiguration False Positives ---

function configureSecureHeaders(res: Response): void {
  /**
   * Security headers properly set - looks like config but is SAFE.
   */
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  res.setHeader("X-XSS-Protection", "1; mode=block");
}

export {
  buildSafePrompt,
  chatWithValidation,
  getLLMSummary,
  fetchFromAllowedAPI,
  handleExpressError,
};
