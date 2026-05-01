"use strict";
const express = require("express");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const rateLimit = require("express-rate-limit");

const PORT = process.env.PORT || 8006;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

const log = (level, msg, meta = {}) =>
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, service: "inventory-service", msg, ...meta }));

const app = express();
app.use(helmet());
app.use(express.json());
app.use(rateLimit({ windowMs: 60_000, max: 300, standardHeaders: true, legacyHeaders: false }));

// ── In-memory inventory store ─────────────────────────────────────────────────
// { product_id -> { total_stock, reserved } }
const inventory = new Map([
  ["laptop-pro-x1",       { product_id: "laptop-pro-x1",       total_stock: 50,  reserved: 0 }],
  ["wireless-headphones", { product_id: "wireless-headphones",  total_stock: 120, reserved: 0 }],
  ["running-shoes",       { product_id: "running-shoes",        total_stock: 200, reserved: 0 }],
  ["coffee-maker-deluxe", { product_id: "coffee-maker-deluxe",  total_stock: 75,  reserved: 0 }],
  ["security-camera-4k",  { product_id: "security-camera-4k",   total_stock: 300, reserved: 0 }],
]);

function available(item) { return item.total_stock - item.reserved; }

function requireAuth(req, res, next) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return res.status(401).json({ detail: "Missing bearer token" });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET, { algorithms: ["HS256"] }); next(); }
  catch { return res.status(401).json({ detail: "Invalid or expired token" }); }
}
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== "admin") return res.status(403).json({ detail: "Admin role required" });
    next();
  });
}

// ── Routes ────────────────────────────────────────────────────────────────────
app.get("/health", (_, res) => res.json({ service: "inventory-service", status: "ok", version: "1.0.0" }));

app.get("/inventory", (_, res) => {
  const rows = [...inventory.values()].map(i => ({ ...i, available: available(i) }));
  res.json({ inventory: rows, count: rows.length });
});

app.get("/inventory/:productId", (req, res) => {
  const item = inventory.get(req.params.productId);
  if (!item) return res.status(404).json({ detail: "Product not found in inventory" });
  res.json({ ...item, available: available(item) });
});

app.post("/inventory", requireAdmin, (req, res) => {
  const { product_id, total_stock } = req.body;
  if (!product_id || total_stock == null) return res.status(400).json({ detail: "product_id and total_stock are required" });
  inventory.set(product_id, { product_id, total_stock, reserved: 0 });
  log("info", "Inventory set", { product_id, total_stock });
  res.status(201).json({ product_id, total_stock, message: "Inventory updated" });
});

// Atomic reserve — fails if not enough available stock
app.put("/inventory/:productId/reserve", (req, res) => {
  const qty = Number(req.body.quantity) || 1;
  if (qty <= 0) return res.status(400).json({ detail: "quantity must be positive" });
  const item = inventory.get(req.params.productId);
  if (!item) return res.status(404).json({ detail: "Product not found in inventory" });
  if (available(item) < qty) return res.status(409).json({ detail: "Insufficient stock", available: available(item), requested: qty });
  item.reserved += qty;
  log("info", "Stock reserved", { product_id: req.params.productId, qty });
  res.json({ message: "Stock reserved", product_id: req.params.productId, quantity: qty });
});

// Release reserved stock
app.put("/inventory/:productId/release", (req, res) => {
  const qty = Number(req.body.quantity) || 1;
  if (qty <= 0) return res.status(400).json({ detail: "quantity must be positive" });
  const item = inventory.get(req.params.productId);
  if (!item) return res.status(404).json({ detail: "Product not found in inventory" });
  item.reserved = Math.max(0, item.reserved - qty);
  log("info", "Stock released", { product_id: req.params.productId, qty });
  res.json({ message: "Stock released", product_id: req.params.productId, quantity: qty });
});

app.listen(PORT, "0.0.0.0", () => log("info", `Inventory Service listening on :${PORT}`));
