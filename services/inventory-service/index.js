/**
 * Inventory Service — SecureShop
 * Responsibilities: Stock levels, reservation, release
 * Language: Node.js 20 / Express  |  Port: 8006
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
const PORT = process.env.PORT || 8006;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me"; // nosec
const DB_DIR = process.env.DATABASE_DIR || "/data";
const DB_PATH = path.join(DB_DIR, "inventory.db");

const log = (level, msg, meta = {}) => {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, service: "inventory-service", msg, ...meta }));
};

// ── Express App ───────────────────────────────────────────────────────────────
const app = express();
app.use(helmet());
app.use(express.json());
app.use(rateLimit({ windowMs: 60_000, max: 300, standardHeaders: true, legacyHeaders: false }));

// ── Database init ─────────────────────────────────────────────────────────────
fs.mkdirSync(DB_DIR, { recursive: true });
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL"); // Better concurrency for reserve/release

db.exec(`
  CREATE TABLE IF NOT EXISTS inventory (
    product_id    TEXT PRIMARY KEY,
    total_stock   INTEGER NOT NULL DEFAULT 0,
    reserved      INTEGER NOT NULL DEFAULT 0,
    updated_at    TEXT NOT NULL
  );
`);

// Seed inventory matching product-service seeded items
const seedInventory = [
  { product_id: "laptop-pro-x1",        total_stock: 50,  reserved: 0 },
  { product_id: "wireless-headphones",   total_stock: 120, reserved: 0 },
  { product_id: "running-shoes",         total_stock: 200, reserved: 0 },
  { product_id: "coffee-maker-deluxe",   total_stock: 75,  reserved: 0 },
  { product_id: "security-camera-4k",    total_stock: 300, reserved: 0 },
];

const insertInventory = db.prepare(
  "INSERT OR IGNORE INTO inventory (product_id,total_stock,reserved,updated_at) VALUES (@product_id,@total_stock,@reserved,@updated_at)"
);
const seedTx = db.transaction((items) => {
  for (const item of items) insertInventory.run({ ...item, updated_at: new Date().toISOString() });
});
seedTx(seedInventory);
log("info", `Inventory DB ready at ${DB_PATH}`);

// ── JWT Middleware ─────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) return res.status(401).json({ detail: "Missing bearer token" });
  try {
    req.user = jwt.verify(authHeader.slice(7), JWT_SECRET, { algorithms: ["HS256"] });
    next();
  } catch {
    return res.status(401).json({ detail: "Invalid or expired token" });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== "admin") return res.status(403).json({ detail: "Admin role required" });
    next();
  });
}

// ── Routes ────────────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ service: "inventory-service", status: "ok", version: "1.0.0" });
});

// GET /inventory — list all inventory
app.get("/inventory", (req, res) => {
  const rows = db.prepare("SELECT *, (total_stock - reserved) AS available FROM inventory").all();
  res.json({ inventory: rows, count: rows.length });
});

// GET /inventory/:productId
app.get("/inventory/:productId", (req, res) => {
  const row = db.prepare(
    "SELECT *, (total_stock - reserved) AS available FROM inventory WHERE product_id = ?"
  ).get(req.params.productId);
  if (!row) return res.status(404).json({ detail: "Product not found in inventory" });
  res.json(row);
});

// POST /inventory — set/create inventory record (admin)
app.post("/inventory", requireAdmin, (req, res) => {
  const { product_id, total_stock } = req.body;
  if (!product_id || total_stock == null) {
    return res.status(400).json({ detail: "product_id and total_stock are required" });
  }
  const now = new Date().toISOString();
  db.prepare(
    "INSERT OR REPLACE INTO inventory (product_id,total_stock,reserved,updated_at) VALUES (?,?,0,?)"
  ).run(product_id, total_stock, now);
  log("info", "Inventory set", { product_id, total_stock });
  res.status(201).json({ product_id, total_stock, message: "Inventory updated" });
});

// PUT /inventory/:productId/reserve — atomically reserve stock
app.put("/inventory/:productId/reserve", (req, res) => {
  const { quantity = 1 } = req.body;
  if (quantity <= 0) return res.status(400).json({ detail: "quantity must be positive" });

  const now = new Date().toISOString();
  // Atomic: only update if available stock >= quantity
  const info = db.prepare(`
    UPDATE inventory
    SET reserved = reserved + ?, updated_at = ?
    WHERE product_id = ? AND (total_stock - reserved) >= ?
  `).run(quantity, now, req.params.productId, quantity);

  if (info.changes === 0) {
    const row = db.prepare("SELECT * FROM inventory WHERE product_id = ?").get(req.params.productId);
    if (!row) return res.status(404).json({ detail: "Product not found in inventory" });
    return res.status(409).json({
      detail: "Insufficient stock",
      available: row.total_stock - row.reserved,
      requested: quantity,
    });
  }

  log("info", "Stock reserved", { product_id: req.params.productId, quantity });
  res.json({ message: "Stock reserved", product_id: req.params.productId, quantity });
});

// PUT /inventory/:productId/release — release previously reserved stock
app.put("/inventory/:productId/release", (req, res) => {
  const { quantity = 1 } = req.body;
  if (quantity <= 0) return res.status(400).json({ detail: "quantity must be positive" });

  const now = new Date().toISOString();
  const info = db.prepare(`
    UPDATE inventory
    SET reserved = MAX(0, reserved - ?), updated_at = ?
    WHERE product_id = ?
  `).run(quantity, now, req.params.productId);

  if (info.changes === 0) return res.status(404).json({ detail: "Product not found in inventory" });

  log("info", "Stock released", { product_id: req.params.productId, quantity });
  res.json({ message: "Stock released", product_id: req.params.productId, quantity });
});

// ── Start Server ──────────────────────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => log("info", `Inventory Service listening on port ${PORT}`));
