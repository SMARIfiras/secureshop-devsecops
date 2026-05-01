"use strict";
const express = require("express");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const rateLimit = require("express-rate-limit");

const PORT = process.env.PORT || 8004;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

const log = (level, msg, meta = {}) =>
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, service: "payment-service", msg, ...meta }));

const app = express();
app.use(helmet());
app.use(express.json());
app.use(rateLimit({ windowMs: 60_000, max: 100, standardHeaders: true, legacyHeaders: false }));

// ── In-memory store ───────────────────────────────────────────────────────────
const payments = new Map();          // id -> payment
const idempotencyIndex = new Map();  // idempotency_key -> id

function requireAuth(req, res, next) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return res.status(401).json({ detail: "Missing bearer token" });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET, { algorithms: ["HS256"] }); next(); }
  catch { return res.status(401).json({ detail: "Invalid or expired token" }); }
}

// ── Routes ────────────────────────────────────────────────────────────────────
app.get("/health", (_, res) => res.json({ service: "payment-service", status: "ok", version: "1.0.0" }));

app.post("/payments", requireAuth, (req, res) => {
  const { order_id, amount, currency = "USD", method = "card", idempotency_key } = req.body;
  if (!order_id || amount == null) return res.status(400).json({ detail: "order_id and amount are required" });
  if (amount <= 0) return res.status(400).json({ detail: "Amount must be positive" });

  if (idempotency_key && idempotencyIndex.has(idempotency_key)) {
    const existing = payments.get(idempotencyIndex.get(idempotency_key));
    return res.status(200).json({ ...existing, _idempotent: true });
  }

  const id = uuidv4();
  const now = new Date().toISOString();
  const payment = { id, order_id, user_id: req.user.sub, amount, currency, status: "completed", idempotency_key: idempotency_key || null, method, created_at: now, updated_at: now };
  payments.set(id, payment);
  if (idempotency_key) idempotencyIndex.set(idempotency_key, id);

  log("info", "Payment processed", { id, order_id, amount });
  res.status(201).json(payment);
});

app.get("/payments/:id", requireAuth, (req, res) => {
  const p = payments.get(req.params.id);
  if (!p) return res.status(404).json({ detail: "Payment not found" });
  if (p.user_id !== req.user.sub && req.user.role !== "admin") return res.status(403).json({ detail: "Access denied" });
  res.json(p);
});

app.get("/payments", requireAuth, (req, res) => {
  const rows = [...payments.values()].filter(p => p.user_id === req.user.sub);
  res.json({ payments: rows, count: rows.length });
});

app.put("/payments/:id/refund", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ detail: "Admin role required" });
  const p = payments.get(req.params.id);
  if (!p || p.status !== "completed") return res.status(409).json({ detail: "Payment not found or not refundable" });
  p.status = "refunded";
  p.updated_at = new Date().toISOString();
  log("info", "Payment refunded", { id: req.params.id });
  res.json({ message: "Payment refunded", id: req.params.id });
});

app.listen(PORT, "0.0.0.0", () => log("info", `Payment Service listening on :${PORT}`));
