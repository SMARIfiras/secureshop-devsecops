/**
 * Payment Service — SecureShop
 * Responsibilities: Payment initiation, transaction records
 * Language: Node.js 20 / Express  |  Port: 8004
 */
"use strict";

const express = require("express");
const helmet = require("helmet");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

// ── Configuration ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 8004;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me"; // nosec
const DB_DIR = process.env.DATABASE_DIR || "/data";
const DB_PATH = path.join(DB_DIR, "payments.db");

const log = (level, msg, meta = {}) => {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, service: "payment-service", msg, ...meta }));
};

// ── Express App ───────────────────────────────────────────────────────────────
const app = express();
app.use(helmet());
app.use(express.json());
app.use(rateLimit({ windowMs: 60_000, max: 100, standardHeaders: true, legacyHeaders: false }));

// ── Database init ─────────────────────────────────────────────────────────────
fs.mkdirSync(DB_DIR, { recursive: true });
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS payments (
    id              TEXT PRIMARY KEY,
    order_id        TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    amount          REAL NOT NULL,
    currency        TEXT DEFAULT 'USD',
    status          TEXT DEFAULT 'pending',
    idempotency_key TEXT UNIQUE,
    method          TEXT DEFAULT 'card',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
  );
`);
log("info", `Payment DB ready at ${DB_PATH}`);

// ── JWT Middleware ─────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ detail: "Missing bearer token" });
  }
  try {
    req.user = jwt.verify(authHeader.slice(7), JWT_SECRET, { algorithms: ["HS256"] });
    next();
  } catch {
    return res.status(401).json({ detail: "Invalid or expired token" });
  }
}

// ── Routes ────────────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ service: "payment-service", status: "ok", version: "1.0.0" });
});

// POST /payments — initiate a payment
app.post("/payments", requireAuth, (req, res) => {
  const { order_id, amount, currency = "USD", method = "card", idempotency_key } = req.body;
  if (!order_id || amount == null) {
    return res.status(400).json({ detail: "order_id and amount are required" });
  }
  if (amount <= 0) {
    return res.status(400).json({ detail: "Amount must be positive" });
  }

  // Idempotency check
  if (idempotency_key) {
    const existing = db.prepare("SELECT * FROM payments WHERE idempotency_key = ?").get(idempotency_key);
    if (existing) {
      return res.status(200).json({ ...existing, _idempotent: true });
    }
  }

  const id = uuidv4();
  const now = new Date().toISOString();
  // Simulate payment processing — in production this calls a payment gateway
  const status = "completed"; // Simulated success

  db.prepare(
    "INSERT INTO payments (id,order_id,user_id,amount,currency,status,idempotency_key,method,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)"
  ).run(id, order_id, req.user.sub, amount, currency, status, idempotency_key || null, method, now, now);

  log("info", "Payment processed", { id, order_id, amount, status });
  res.status(201).json({ id, order_id, amount, currency, status, method, created_at: now });
});

// GET /payments/:id — get a transaction
app.get("/payments/:id", requireAuth, (req, res) => {
  const row = db.prepare("SELECT * FROM payments WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ detail: "Payment not found" });
  // Users can only view their own payments; admins can view all
  if (row.user_id !== req.user.sub && req.user.role !== "admin") {
    return res.status(403).json({ detail: "Access denied" });
  }
  res.json(row);
});

// GET /payments — list payments for current user
app.get("/payments", requireAuth, (req, res) => {
  const rows = db.prepare(
    "SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC LIMIT 50"
  ).all(req.user.sub);
  res.json({ payments: rows, count: rows.length });
});

// PUT /payments/:id/refund (admin only)
app.put("/payments/:id/refund", requireAuth, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ detail: "Admin role required" });
  const now = new Date().toISOString();
  const info = db.prepare(
    "UPDATE payments SET status='refunded', updated_at=? WHERE id=? AND status='completed'"
  ).run(now, req.params.id);
  if (info.changes === 0) return res.status(409).json({ detail: "Payment not found or not refundable" });
  log("info", "Payment refunded", { id: req.params.id });
  res.json({ message: "Payment refunded", id: req.params.id });
});

// ── Start Server ──────────────────────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => log("info", `Payment Service listening on port ${PORT}`));
