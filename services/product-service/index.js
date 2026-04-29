/**
 * Product Service — SecureShop
 * Responsibilities: Product catalogue, search, categories
 * Language: Node.js 20 / Express  |  Port: 8002
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
const PORT = process.env.PORT || 8002;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me"; // SAST: semgrep will flag hardcoded default
const DB_DIR = process.env.DATABASE_DIR || "/data";
const DB_PATH = path.join(DB_DIR, "products.db");

// ── Logging helper ────────────────────────────────────────────────────────────
const log = (level, msg, meta = {}) => {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, service: "product-service", msg, ...meta }));
};

// ── Express App ───────────────────────────────────────────────────────────────
const app = express();
app.use(helmet());
app.use(express.json());
app.use(rateLimit({ windowMs: 60_000, max: 200, standardHeaders: true, legacyHeaders: false }));

// ── Database init ─────────────────────────────────────────────────────────────
fs.mkdirSync(DB_DIR, { recursive: true });
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS products (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    price       REAL NOT NULL,
    category    TEXT DEFAULT 'general',
    stock       INTEGER DEFAULT 0,
    created_at  TEXT NOT NULL
  );
`);

// Seed demo products
const seedProducts = [
  { id: uuidv4(), name: "Laptop Pro X1", description: "High-performance laptop", price: 1299.99, category: "electronics", stock: 50 },
  { id: uuidv4(), name: "Wireless Headphones", description: "Noise-cancelling headphones", price: 249.99, category: "electronics", stock: 120 },
  { id: uuidv4(), name: "Running Shoes", description: "Lightweight running shoes", price: 89.99, category: "footwear", stock: 200 },
  { id: uuidv4(), name: "Coffee Maker Deluxe", description: "Programmable coffee machine", price: 149.99, category: "home", stock: 75 },
  { id: uuidv4(), name: "Security Camera 4K", description: "Indoor/outdoor IP camera", price: 79.99, category: "security", stock: 300 },
];

const insertProduct = db.prepare(
  "INSERT OR IGNORE INTO products (id,name,description,price,category,stock,created_at) VALUES (@id,@name,@description,@price,@category,@stock,@created_at)"
);
const seedTx = db.transaction((products) => {
  for (const p of products) insertProduct.run({ ...p, created_at: new Date().toISOString() });
});
seedTx(seedProducts);
log("info", `DB ready at ${DB_PATH}`);

// ── JWT Middleware ─────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ detail: "Missing bearer token" });
  }
  try {
    req.user = jwt.verify(authHeader.slice(7), JWT_SECRET, { algorithms: ["HS256"] });
    next();
  } catch (err) {
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
  res.json({ service: "product-service", status: "ok", version: "1.0.0" });
});

// GET /products?category=electronics
app.get("/products", (req, res) => {
  const { category, limit = 50, offset = 0 } = req.query;
  let rows;
  if (category) {
    rows = db.prepare("SELECT * FROM products WHERE category = ? LIMIT ? OFFSET ?")
             .all(category, Number(limit), Number(offset));
  } else {
    rows = db.prepare("SELECT * FROM products LIMIT ? OFFSET ?").all(Number(limit), Number(offset));
  }
  res.json({ products: rows, count: rows.length });
});

// GET /products/search?q=laptop
app.get("/products/search", (req, res) => {
  const q = `%${req.query.q || ""}%`;
  const rows = db.prepare(
    "SELECT * FROM products WHERE name LIKE ? OR description LIKE ? LIMIT 20"
  ).all(q, q);
  res.json({ products: rows, count: rows.length });
});

// GET /products/:id
app.get("/products/:id", (req, res) => {
  const row = db.prepare("SELECT * FROM products WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ detail: "Product not found" });
  res.json(row);
});

// POST /products  (admin only)
app.post("/products", requireAdmin, (req, res) => {
  const { name, description, price, category, stock } = req.body;
  if (!name || price == null) return res.status(400).json({ detail: "name and price are required" });
  const id = uuidv4();
  db.prepare(
    "INSERT INTO products (id,name,description,price,category,stock,created_at) VALUES (?,?,?,?,?,?,?)"
  ).run(id, name, description || "", price, category || "general", stock || 0, new Date().toISOString());
  log("info", "Product created", { id, name });
  res.status(201).json({ id, message: "Product created" });
});

// PUT /products/:id  (admin only)
app.put("/products/:id", requireAdmin, (req, res) => {
  const { name, description, price, category, stock } = req.body;
  const existing = db.prepare("SELECT id FROM products WHERE id = ?").get(req.params.id);
  if (!existing) return res.status(404).json({ detail: "Product not found" });
  db.prepare(
    "UPDATE products SET name=COALESCE(?,name), description=COALESCE(?,description), price=COALESCE(?,price), category=COALESCE(?,category), stock=COALESCE(?,stock) WHERE id=?"
  ).run(name, description, price, category, stock, req.params.id);
  res.json({ message: "Product updated" });
});

// DELETE /products/:id  (admin only)
app.delete("/products/:id", requireAdmin, (req, res) => {
  db.prepare("DELETE FROM products WHERE id = ?").run(req.params.id);
  res.json({ message: "Product deleted" });
});

// ── Start Server ──────────────────────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => log("info", `Product Service listening on port ${PORT}`));
