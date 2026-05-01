"use strict";
const express = require("express");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const rateLimit = require("express-rate-limit");

const PORT = process.env.PORT || 8002;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

const log = (level, msg, meta = {}) =>
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, service: "product-service", msg, ...meta }));

const app = express();
app.use(helmet());
app.use(express.json());
app.use(rateLimit({ windowMs: 60_000, max: 200, standardHeaders: true, legacyHeaders: false }));

// ── In-memory store ───────────────────────────────────────────────────────────
const products = new Map([
  ["laptop-pro-x1",      { id: "laptop-pro-x1",      name: "Laptop Pro X1",        description: "High-performance laptop",          price: 1299.99, category: "electronics", stock: 50,  created_at: new Date().toISOString() }],
  ["wireless-headphones",{ id: "wireless-headphones", name: "Wireless Headphones",   description: "Noise-cancelling headphones",      price: 249.99,  category: "electronics", stock: 120, created_at: new Date().toISOString() }],
  ["running-shoes",      { id: "running-shoes",       name: "Running Shoes",         description: "Lightweight running shoes",        price: 89.99,   category: "footwear",    stock: 200, created_at: new Date().toISOString() }],
  ["coffee-maker-deluxe",{ id: "coffee-maker-deluxe", name: "Coffee Maker Deluxe",  description: "Programmable coffee machine",      price: 149.99,  category: "home",        stock: 75,  created_at: new Date().toISOString() }],
  ["security-camera-4k", { id: "security-camera-4k",  name: "Security Camera 4K",   description: "Indoor/outdoor IP camera",         price: 79.99,   category: "security",    stock: 300, created_at: new Date().toISOString() }],
]);

// ── JWT helpers ───────────────────────────────────────────────────────────────
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
app.get("/health", (_, res) => res.json({ service: "product-service", status: "ok", version: "1.0.0" }));

app.get("/products", (req, res) => {
  const { category, limit = 50, offset = 0 } = req.query;
  let rows = [...products.values()];
  if (category) rows = rows.filter(p => p.category === category);
  rows = rows.slice(Number(offset), Number(offset) + Number(limit));
  res.json({ products: rows, count: rows.length });
});

app.get("/products/search", (req, res) => {
  const q = (req.query.q || "").toLowerCase();
  const rows = [...products.values()].filter(p =>
    p.name.toLowerCase().includes(q) || p.description.toLowerCase().includes(q)
  ).slice(0, 20);
  res.json({ products: rows, count: rows.length });
});

app.get("/products/:id", (req, res) => {
  const p = products.get(req.params.id);
  if (!p) return res.status(404).json({ detail: "Product not found" });
  res.json(p);
});

app.post("/products", requireAdmin, (req, res) => {
  const { name, description, price, category, stock } = req.body;
  if (!name || price == null) return res.status(400).json({ detail: "name and price are required" });
  const id = uuidv4();
  const p = { id, name, description: description || "", price, category: category || "general", stock: stock || 0, created_at: new Date().toISOString() };
  products.set(id, p);
  log("info", "Product created", { id, name });
  res.status(201).json({ id, message: "Product created" });
});

app.put("/products/:id", requireAdmin, (req, res) => {
  const p = products.get(req.params.id);
  if (!p) return res.status(404).json({ detail: "Product not found" });
  Object.assign(p, req.body);
  res.json({ message: "Product updated" });
});

app.delete("/products/:id", requireAdmin, (req, res) => {
  products.delete(req.params.id);
  res.json({ message: "Product deleted" });
});

app.listen(PORT, "0.0.0.0", () => log("info", `Product Service listening on :${PORT}`));
