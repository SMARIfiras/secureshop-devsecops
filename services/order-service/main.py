"""
Order Service — SecureShop
Responsibilities: Cart management, Order lifecycle, Event publishing
Language: Python 3.12 / FastAPI  |  Port: 8003
"""
import os
import sqlite3
import logging
import uuid
import json
import datetime
from typing import List, Optional
from contextlib import contextmanager

import httpx
import pika
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import jwt, JWTError

# ── Configuration ────────────────────────────────────────────────────────────
SECRET_KEY: str = os.environ.get("JWT_SECRET", "dev-secret-change-me")  # nosec B105
ALGORITHM: str = "HS256"
DB_PATH: str = os.environ.get("DATABASE_URL", "/data/orders.db")
INVENTORY_URL: str = os.environ.get("INVENTORY_SERVICE_URL", "http://inventory-service:8006")
RABBITMQ_URL: str = os.environ.get("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")  # nosec B106

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s %(message)s")
logger = logging.getLogger("order-service")

app = FastAPI(title="Order Service", version="1.0.0")
bearer_scheme = HTTPBearer()

# ── Database ──────────────────────────────────────────────────────────────────
@contextmanager
def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id          TEXT PRIMARY KEY,
                user_id     TEXT NOT NULL,
                items       TEXT NOT NULL,
                status      TEXT DEFAULT 'pending',
                total       REAL NOT NULL,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            )
        """)
        conn.commit()
    logger.info("Order DB ready at %s", DB_PATH)


# ── Pydantic Models ───────────────────────────────────────────────────────────
class OrderItem(BaseModel):
    product_id: str
    quantity: int
    unit_price: float


class CreateOrderRequest(BaseModel):
    items: List[OrderItem]


class OrderResponse(BaseModel):
    id: str
    user_id: str
    items: list
    status: str
    total: float
    created_at: str
    updated_at: str


# ── JWT Helper ────────────────────────────────────────────────────────────────
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc


# ── RabbitMQ Publisher ───────────────────────────────────────────────────────
def publish_order_event(event: dict) -> None:
    """Publish an order event to RabbitMQ (best-effort)."""
    try:
        params = pika.URLParameters(RABBITMQ_URL)
        conn = pika.BlockingConnection(params)
        channel = conn.channel()
        channel.queue_declare(queue="notifications", durable=True)
        channel.basic_publish(
            exchange="",
            routing_key="notifications",
            body=json.dumps(event),
            properties=pika.BasicProperties(delivery_mode=2),  # persistent
        )
        conn.close()
        logger.info("Published order event: %s", event.get("type"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("RabbitMQ publish failed (non-fatal): %s", exc)


# ── Inventory reservation ────────────────────────────────────────────────────
def reserve_stock(product_id: str, quantity: int) -> bool:
    try:
        resp = httpx.put(
            f"{INVENTORY_URL}/inventory/{product_id}/reserve",
            json={"quantity": quantity},
            timeout=5,
        )
        return resp.status_code == 200
    except Exception as exc:  # noqa: BLE001
        logger.warning("Inventory reserve failed: %s", exc)
        return False


# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    init_db()


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health_check():
    return {"service": "order-service", "status": "ok", "version": "1.0.0"}


@app.post("/orders", status_code=status.HTTP_201_CREATED)
def create_order(req: CreateOrderRequest, payload: dict = Depends(verify_token)):
    """Create a new order. Reserves inventory and publishes notification event."""
    user_id = payload["sub"]
    order_id = str(uuid.uuid4())
    now = datetime.datetime.utcnow().isoformat()

    # Validate & calculate total
    if not req.items:
        raise HTTPException(status_code=400, detail="Order must contain at least one item")
    total = sum(item.quantity * item.unit_price for item in req.items)

    # Reserve inventory for each item
    for item in req.items:
        if not reserve_stock(item.product_id, item.quantity):
            raise HTTPException(status_code=409, detail=f"Insufficient stock for product {item.product_id}")

    items_json = json.dumps([i.model_dump() for i in req.items])
    with get_db() as conn:
        conn.execute(
            "INSERT INTO orders (id,user_id,items,status,total,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
            (order_id, user_id, items_json, "pending", total, now, now),
        )
        conn.commit()

    # Publish async notification event
    publish_order_event({
        "type": "ORDER_CREATED",
        "order_id": order_id,
        "user_id": user_id,
        "total": total,
        "timestamp": now,
    })

    logger.info("Order created: %s by user %s", order_id, user_id)
    return {"id": order_id, "status": "pending", "total": total, "message": "Order created"}


@app.get("/orders")
def list_orders(payload: dict = Depends(verify_token)):
    """List orders for the authenticated user."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC", (payload["sub"],)
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/orders/{order_id}")
def get_order(order_id: str, payload: dict = Depends(verify_token)):
    """Get a specific order (must belong to the requesting user)."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Order not found")
    if row["user_id"] != payload["sub"] and payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    return dict(row)


@app.put("/orders/{order_id}/cancel")
def cancel_order(order_id: str, payload: dict = Depends(verify_token)):
    """Cancel a pending order."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Order not found")
        if row["user_id"] != payload["sub"] and payload.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Access denied")
        if row["status"] not in ("pending",):
            raise HTTPException(status_code=409, detail=f"Cannot cancel order with status '{row['status']}'")
        now = datetime.datetime.utcnow().isoformat()
        conn.execute("UPDATE orders SET status='cancelled', updated_at=? WHERE id=?", (now, order_id))
        conn.commit()

    publish_order_event({"type": "ORDER_CANCELLED", "order_id": order_id, "timestamp": now})
    return {"message": "Order cancelled", "order_id": order_id}
