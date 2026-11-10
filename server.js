import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";

const PORT = Number.parseInt(process.env.PORT || "3000", 10);
const API_BASE = "https://payments.relworx.com/api/mobile-money";
const DEFAULT_FRONTEND_ORIGIN = "https://relworkx.onrender.com";
const WEBHOOK_TTL_MS = 30 * 60 * 1000;
const MAX_WEBHOOK_RECEIPTS = 5000;
const MAX_BODY_BYTES = 16 * 1024;
const PAYMENT_WINDOW_MS = 10 * 60 * 1000;
const MAX_COLLECTIONS_PER_PHONE = 5;
const REFERENCE_TTL_MS = 24 * 60 * 60 * 1000;

// This in-memory cache is only a convenience for quick receipt lookups.
// Relworx remains the source of truth; status checks fall back to its API.
const webhookReceipts = new Map();
const phoneRequestTimes = new Map();
const usedReferences = new Map();

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...extraHeaders,
  });
  res.end(body);
}

function configuredFrontendOrigins() {
  const configured = (process.env.FRONTEND_ORIGIN || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
    .map((origin) => {
      try {
        return new URL(origin).origin;
      } catch {
        return "";
      }
    })
    .filter(Boolean);
  return [...new Set([DEFAULT_FRONTEND_ORIGIN, ...configured])];
}

function applyCors(req, res) {
  const requestOrigin = req.headers.origin;
  if (!requestOrigin) return true;

  const allowedOrigins = configuredFrontendOrigins();
  const forwardedProtocol = String(req.headers["x-forwarded-proto"] || "http")
    .split(",")[0]
    .trim();
  const sameOrigin = requestOrigin === `${forwardedProtocol}://${req.headers.host}`;
  if (!sameOrigin && !allowedOrigins.includes(requestOrigin)) {
    sendJson(res, 403, {
      success: false,
      error: "ORIGIN_NOT_ALLOWED",
      message: "This frontend origin is not allowed.",
    });
    return false;
  }

  res.setHeader("access-control-allow-origin", requestOrigin);
  res.setHeader("vary", "Origin");
  res.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
  res.setHeader("access-control-allow-headers", "Authorization, Content-Type");
  res.setHeader("access-control-max-age", "600");
  return true;
}

function isAuthorized(req) {
  const expectedToken = process.env.PAYMENT_API_TOKEN;
  if (!expectedToken) return false;

  const authorization = req.headers.authorization || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) return false;

  const supplied = Buffer.from(match[1]);
  const expected = Buffer.from(expectedToken);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

function requireApiToken(req, res, { allowPublicCheckout = false } = {}) {
  if (isAuthorized(req)) return true;
  if (allowPublicCheckout && process.env.PUBLIC_CHECKOUT_ENABLED === "true") return true;

  if (!process.env.PAYMENT_API_TOKEN) {
    sendJson(res, 503, {
      success: false,
      error: "PAYMENT_API_AUTH_NOT_CONFIGURED",
      message:
        "Set PAYMENT_API_TOKEN for private API access, or explicitly enable the public checkout with PUBLIC_CHECKOUT_ENABLED=true.",
    });
    return false;
  }

  sendJson(res, 401, {
    success: false,
    error: "UNAUTHORIZED",
    message: "A valid Bearer token is required.",
  });
  return false;
}

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooLarge = false;
    const chunks = [];

    req.on("data", (chunk) => {
      if (tooLarge) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        tooLarge = true;
        reject(Object.assign(new Error("Request body is too large."), { statusCode: 413 }));
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      if (tooLarge) return;
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(Object.assign(new Error("Request body must be valid JSON."), { statusCode: 400 }));
      }
    });

    req.on("error", reject);
  });
}

function validatePaymentInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { error: "Request body must be a JSON object." };
  }

  const sensitiveField = Object.keys(input).find((key) =>
    /^(pin|otp|password|passcode)$/i.test(key),
  );
  if (sensitiveField) {
    return {
      error:
        "Do not send a mobile-money PIN or one-time code to this server. The customer enters it only in the operator's phone prompt.",
    };
  }

  const country = String(input.country || "").trim().toUpperCase();
  if (["RW", "RWA", "RWANDA"].includes(country)) {
    return {
      unsupportedCountry: true,
      error:
        "Rwanda is listed in Relworx's overview, but its Request Payment endpoint currently documents only UGX, KES, and TZS. Confirm RWF support with Relworx before enabling collections.",
    };
  }

  if (["CD", "DRC", "DRC CONGO", "CONGO DR", "DEMOCRATIC REPUBLIC OF THE CONGO"].includes(country)) {
    return {
      unsupportedCountry: true,
      error:
        "DR Congo is listed in Relworx's overview, but its Request Payment endpoint currently documents only UGX, KES, and TZS. Confirm DRC collection support with Relworx before enabling it.",
    };
  }

  let countryConfig;
  if (["TZ", "TZA", "TANZANIA"].includes(country)) {
    countryConfig = {
      country: "TZ",
      countryName: "Tanzania",
      currency: "TZS",
      phonePattern: /^\+255[67]\d{8}$/,
      minimum: 500,
      maximum: 5_000_000,
    };
  } else if (["KE", "KEN", "KENYA"].includes(country)) {
    countryConfig = {
      country: "KE",
      countryName: "Kenya",
      currency: "KES",
      phonePattern: /^\+254[17]\d{8}$/,
      minimum: 10,
      maximum: 70_000,
    };
  } else if (["UG", "UGA", "UGANDA"].includes(country)) {
    countryConfig = {
      country: "UG",
      countryName: "Uganda",
      currency: "UGX",
      phonePattern: /^\+256\d{9}$/,
      minimum: 500,
      maximum: 5_000_000,
    };
  } else {
    return {
      error: "Supported collection countries are Tanzania (TZ), Kenya (KE), and Uganda (UG).",
    };
  }

  const msisdn = String(input.msisdn || "").trim();
  if (!countryConfig.phonePattern.test(msisdn)) {
    return {
      error:
        countryConfig.country === "KE"
          ? "Kenya mobile number must use international format, for example +254712345678."
          : countryConfig.country === "UG"
            ? "Uganda mobile number must use international format, for example +256701234567."
            : "Tanzania mobile number must use international format, for example +255712345678.",
    };
  }

  const amount = Number(input.amount);
  if (
    !Number.isFinite(amount) ||
    amount < countryConfig.minimum ||
    amount > countryConfig.maximum
  ) {
    return {
      error: `${countryConfig.countryName} collection amount must be between ${countryConfig.currency} ${countryConfig.minimum.toLocaleString("en")} and ${countryConfig.currency} ${countryConfig.maximum.toLocaleString("en")}.`,
    };
  }
  if (Math.round(amount * 100) !== amount * 100) {
    return { error: "Amount may have no more than two decimal places." };
  }

  let reference = input.reference == null ? randomUUID() : String(input.reference).trim();
  if (!/^[A-Za-z0-9_-]{8,36}$/.test(reference)) {
    return { error: "Reference must be 8–36 characters using letters, numbers, hyphens, or underscores." };
  }

  const description = input.description == null ? undefined : String(input.description).trim();
  if (description && description.length > 255) {
    return { error: "Description must be 255 characters or fewer." };
  }

  return {
    value: {
      country: countryConfig.country,
      msisdn,
      amount,
      currency: countryConfig.currency,
      reference,
      ...(description ? { description } : {}),
    },
  };
}

function checkAndRecordPhoneRateLimit(msisdn) {
  const now = Date.now();
  const recent = (phoneRequestTimes.get(msisdn) || []).filter(
    (time) => now - time < PAYMENT_WINDOW_MS,
  );
  if (recent.length >= MAX_COLLECTIONS_PER_PHONE) {
    phoneRequestTimes.set(msisdn, recent);
    return false;
  }

  recent.push(now);
  phoneRequestTimes.set(msisdn, recent);
  return true;
}

function requireLiveRelworxConfig(res) {
  if (process.env.RELWORX_LIVE_PAYMENTS !== "true") {
    sendJson(res, 503, {
      success: false,
      error: "LIVE_PAYMENTS_DISABLED",
      message: "Live requests are disabled. Set RELWORX_LIVE_PAYMENTS=true after configuring your Relworx account.",
    });
    return false;
  }

  if (!process.env.RELWORX_API_KEY || !process.env.RELWORX_ACCOUNT_NO) {
    sendJson(res, 503, {
      success: false,
      error: "RELWORX_CONFIGURATION_MISSING",
      message: "Set RELWORX_API_KEY and RELWORX_ACCOUNT_NO in the server environment.",
    });
    return false;
  }

  return true;
}

async function requestRelworx(path, options = {}) {
  return fetch(`${API_BASE}${path}`, {
    ...options,
    signal: AbortSignal.timeout(20_000),
    headers: {
      Accept: "application/vnd.relworx.v2",
      Authorization: `Bearer ${process.env.RELWORX_API_KEY}`,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });
}

async function validateUgandaSubscriber(msisdn) {
  const upstream = await requestRelworx("/validate", {
    method: "POST",
    body: JSON.stringify({ msisdn }),
  });
  const responseText = await upstream.text();
  let providerResponse = {};
  try {
    providerResponse = responseText ? JSON.parse(responseText) : {};
  } catch {
    // Do not expose provider HTML or unexpected response bodies to the customer.
  }

  // Relworx's response may include customer_name; return only validation status/message.
  return {
    valid: upstream.ok && providerResponse.success === true,
    status: upstream.status,
    message:
      typeof providerResponse.message === "string"
        ? providerResponse.message
        : "Relworx could not verify this mobile-money number.",
  };
}

async function forwardRelworxResponse(res, upstream) {
  const responseBody = await upstream.text();
  res.writeHead(upstream.status, {
    "content-type": upstream.headers.get("content-type") || "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(responseBody);
}

function trimWebhookReceipts() {
  const cutoff = Date.now() - WEBHOOK_TTL_MS;
  for (const [reference, entry] of webhookReceipts) {
    if (entry.receivedAt < cutoff) webhookReceipts.delete(reference);
  }

  while (webhookReceipts.size > MAX_WEBHOOK_RECEIPTS) {
    const oldestKey = webhookReceipts.keys().next().value;
    if (oldestKey === undefined) break;
    webhookReceipts.delete(oldestKey);
  }
}

function trimUsedReferences() {
  const cutoff = Date.now() - REFERENCE_TTL_MS;
  for (const [reference, usedAt] of usedReferences) {
    if (usedAt < cutoff) usedReferences.delete(reference);
  }
}

function parseRelworxSignature(header) {
  const values = Object.create(null);
  for (const item of String(header || "").split(",")) {
    const separator = item.indexOf("=");
    if (separator === -1) continue;
    values[item.slice(0, separator).trim()] = item.slice(separator + 1).trim();
  }
  return { timestamp: values.t, signature: values.v };
}

function safeEqual(actual, expected) {
  const actualBuffer = Buffer.from(actual);
  const expectedBuffer = Buffer.from(expected);
  return (
    actualBuffer.length === expectedBuffer.length &&
    timingSafeEqual(actualBuffer, expectedBuffer)
  );
}

function verifyWebhook(req, payload) {
  const secret = process.env.RELWORX_WEBHOOK_SECRET;
  const exactWebhookUrl = process.env.RELWORX_WEBHOOK_URL;
  if (!secret || !exactWebhookUrl) return { configured: false, valid: false };

  const { timestamp, signature } = parseRelworxSignature(req.headers["relworx-signature"]);
  if (!timestamp || !signature || !/^\d+$/.test(timestamp)) {
    return { configured: true, valid: false };
  }

  // Reject old signed events to reduce replay risk.
  if (Math.abs(Date.now() - Number(timestamp) * 1000) > 5 * 60 * 1000) {
    return { configured: true, valid: false };
  }

  const signedFields = {
    status: payload.status,
    customer_reference: payload.customer_reference,
    internal_reference: payload.internal_reference,
  };
  if (Object.values(signedFields).some((value) => value == null)) {
    return { configured: true, valid: false };
  }

  const signedData =
    exactWebhookUrl +
    timestamp +
    Object.keys(signedFields)
      .sort()
      .map((key) => `${key}${String(signedFields[key])}`)
      .join("");
  const digest = createHmac("sha256", secret).update(signedData).digest();

  // Relworx's docs show both a hex output and a base64-looking header example.
  const valid =
    safeEqual(signature, digest.toString("hex")) ||
    safeEqual(signature, digest.toString("base64"));
  return { configured: true, valid };
}

async function handleCollect(req, res) {
  if (!requireApiToken(req, res, { allowPublicCheckout: true })) return;

  let input;
  try {
    input = await parseJsonBody(req);
  } catch (error) {
    sendJson(res, error.statusCode || 400, {
      success: false,
      error: error.statusCode === 413 ? "REQUEST_TOO_LARGE" : "INVALID_JSON",
      message: error.message || "Could not read request body.",
    });
    return;
  }

  const validation = validatePaymentInput(input);
  if (validation.unsupportedCountry) {
    sendJson(res, 501, {
      success: false,
      error: "COUNTRY_NOT_CONFIRMED",
      message: validation.error,
    });
    return;
  }
  if (validation.error) {
    sendJson(res, 400, {
      success: false,
      error: "INVALID_PAYMENT_REQUEST",
      message: validation.error,
    });
    return;
  }

  if (!requireLiveRelworxConfig(res)) return;
  trimUsedReferences();
  if (usedReferences.has(validation.value.reference)) {
    sendJson(res, 409, {
      success: false,
      error: "DUPLICATE_REFERENCE",
      message: "This reference was already submitted. Check its transaction status before retrying.",
    });
    return;
  }
  if (!checkAndRecordPhoneRateLimit(validation.value.msisdn)) {
    sendJson(res, 429, {
      success: false,
      error: "PHONE_RATE_LIMITED",
      message: "Maximum 5 collection requests per phone number every 10 minutes.",
    });
    return;
  }

  if (validation.value.country === "UG") {
    try {
      const numberCheck = await validateUgandaSubscriber(validation.value.msisdn);
      if (!numberCheck.valid) {
        sendJson(res, numberCheck.status >= 400 ? numberCheck.status : 400, {
          success: false,
          error:
            numberCheck.status === 401 || numberCheck.status === 403
              ? "RELWORX_API_ACCESS_DENIED"
              : "INVALID_MOBILE_NUMBER",
          message: numberCheck.message,
        });
        return;
      }
    } catch {
      sendJson(res, 502, {
        success: false,
        error: "RELWORX_VALIDATION_UNAVAILABLE",
        message: "Could not verify this Uganda number with Relworx. No payment request was sent.",
      });
      return;
    }
  }

  const relworxPayload = {
    account_no: process.env.RELWORX_ACCOUNT_NO,
    reference: validation.value.reference,
    msisdn: validation.value.msisdn,
    currency: validation.value.currency,
    amount: validation.value.amount,
    ...(validation.value.description ? { description: validation.value.description } : {}),
  };

  // Reserve before calling Relworx so a retry with the same reference cannot
  // accidentally create another collection in this running process.
  usedReferences.set(validation.value.reference, Date.now());

  try {
    const upstream = await requestRelworx("/request-payment", {
      method: "POST",
      body: JSON.stringify(relworxPayload),
    });
    await forwardRelworxResponse(res, upstream);
  } catch {
    sendJson(res, 502, {
      success: false,
      error: "RELWORX_UNAVAILABLE",
      message: "Could not reach Relworx. Check the transaction status before retrying.",
    });
  }
}

async function handleStatus(url, req, res) {
  if (!requireApiToken(req, res, { allowPublicCheckout: true })) return;
  if (!requireLiveRelworxConfig(res)) return;

  const internalReference = url.searchParams.get("internal_reference") || "";
  if (!/^[A-Za-z0-9_-]{8,128}$/.test(internalReference)) {
    sendJson(res, 400, {
      success: false,
      error: "INVALID_INTERNAL_REFERENCE",
      message: "Provide a valid internal_reference returned by Relworx.",
    });
    return;
  }

  trimWebhookReceipts();
  const cachedReceipt = webhookReceipts.get(internalReference);
  if (cachedReceipt) {
    sendJson(res, 200, { success: true, receipt: cachedReceipt.payload });
    return;
  }

  const query = new URLSearchParams({
    internal_reference: internalReference,
    account_no: process.env.RELWORX_ACCOUNT_NO,
  });

  try {
    const upstream = await requestRelworx(`/check-request-status?${query}`, {
      method: "GET",
    });
    await forwardRelworxResponse(res, upstream);
  } catch {
    sendJson(res, 502, {
      success: false,
      error: "RELWORX_UNAVAILABLE",
      message: "Could not reach Relworx to check transaction status.",
    });
  }
}

async function handleWebhook(req, res) {
  let payload;
  try {
    payload = await parseJsonBody(req);
  } catch {
    sendJson(res, 400, {
      success: false,
      error: "INVALID_WEBHOOK_BODY",
      message: "Webhook body must be valid JSON.",
    });
    return;
  }

  const verification = verifyWebhook(req, payload);
  if (!verification.configured) {
    sendJson(res, 503, {
      success: false,
      error: "WEBHOOK_VERIFICATION_NOT_CONFIGURED",
      message: "Set RELWORX_WEBHOOK_SECRET and RELWORX_WEBHOOK_URL before enabling callbacks.",
    });
    return;
  }
  if (!verification.valid) {
    sendJson(res, 401, {
      success: false,
      error: "INVALID_WEBHOOK_SIGNATURE",
      message: "Webhook signature is invalid or expired.",
    });
    return;
  }

  const reference = String(payload.internal_reference || "");
  if (!reference) {
    sendJson(res, 400, {
      success: false,
      error: "MISSING_INTERNAL_REFERENCE",
      message: "Relworx webhook did not include internal_reference.",
    });
    return;
  }

  trimWebhookReceipts();
  webhookReceipts.set(reference, { payload, receivedAt: Date.now() });
  trimWebhookReceipts();
  sendJson(res, 200, { success: true, received: true });
}

async function handleRequest(req, res) {
  if (!applyCors(req, res)) return;

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url || "/", "http://localhost");

  if (req.method === "GET" && url.pathname === "/") {
    sendJson(res, 200, {
      success: true,
      service: "relworx-mobile-money-server",
      message: "Payment API is online. The checkout frontend is hosted separately.",
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/health") {
    sendJson(res, 200, { success: true, service: "relworx-mobile-money-server" });
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/payments/collect") {
    await handleCollect(req, res);
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/payments/status") {
    await handleStatus(url, req, res);
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/relworx/webhook") {
    await handleWebhook(req, res);
    return;
  }

  sendJson(res, 404, {
    success: false,
    error: "NOT_FOUND",
    message: "Route not found.",
  });
}

const server = createServer((req, res) => {
  handleRequest(req, res).catch((error) => {
    process.stderr.write(
      `Request handler failed (${error?.code || error?.name || "UNKNOWN"}).\n`,
    );
    if (!res.headersSent) {
      sendJson(res, 500, {
        success: false,
        error: "INTERNAL_SERVER_ERROR",
        message: "The server could not complete the request.",
      });
    } else {
      res.destroy();
    }
  });
});

server.listen(PORT, "0.0.0.0", () => {
  // No credentials or payment/customer data are logged.
  process.stdout.write(`Relworx mobile-money server listening on port ${PORT}\n`);
});
