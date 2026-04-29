"""
Notification Service — SecureShop
Responsibilities: Email/SMS dispatch via RabbitMQ message queue
Language: Python 3.12 / FastAPI + pika  |  Port: 8005
"""
import os
import json
import logging
import sqlite3
import threading
import time
import uuid
import datetime
from contextlib import contextmanager
from typing import Optional

import pika
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# ── Configuration ────────────────────────────────────────────────────────────
RABBITMQ_URL: str = os.environ.get("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")  # nosec B106
DB_PATH: str = os.environ.get("DATABASE_URL", "/data/notifications.db")
QUEUE_NAME: str = "notifications"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s %(message)s")
logger = logging.getLogger("notification-service")

app = FastAPI(title="Notification Service", version="1.0.0")

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
            CREATE TABLE IF NOT EXISTS notifications (
                id          TEXT PRIMARY KEY,
                type        TEXT NOT NULL,
                recipient   TEXT,
                payload     TEXT,
                status      TEXT DEFAULT 'sent',
                created_at  TEXT NOT NULL
            )
        """)
        conn.commit()
    logger.info("Notification DB ready at %s", DB_PATH)


def save_notification(ntype: str, recipient: Optional[str], payload: dict) -> str:
    nid = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute(
            "INSERT INTO notifications (id,type,recipient,payload,status,created_at) VALUES (?,?,?,?,?,?)",
            (nid, ntype, recipient, json.dumps(payload), "sent", datetime.datetime.utcnow().isoformat()),
        )
        conn.commit()
    return nid


# ── RabbitMQ Consumer ────────────────────────────────────────────────────────
def process_message(body: bytes) -> None:
    """Handle an incoming order event from RabbitMQ."""
    try:
        event = json.loads(body)
        event_type = event.get("type", "UNKNOWN")
        logger.info("Processing event: %s  order=%s", event_type, event.get("order_id"))

        # Simulate sending email/SMS (log only in workshop)
        if event_type == "ORDER_CREATED":
            logger.info(
                "📧 [SIMULATED EMAIL] Order %s created — total %.2f",
                event.get("order_id"), event.get("total", 0),
            )
        elif event_type == "ORDER_CANCELLED":
            logger.info("📧 [SIMULATED EMAIL] Order %s cancelled", event.get("order_id"))

        save_notification(event_type, event.get("user_id"), event)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to process message: %s", exc)


def _rabbitmq_consumer_loop() -> None:
    """Background thread: connects to RabbitMQ and consumes notification messages."""
    while True:
        try:
            logger.info("Connecting to RabbitMQ at %s …", RABBITMQ_URL.split("@")[-1])
            params = pika.URLParameters(RABBITMQ_URL)
            connection = pika.BlockingConnection(params)
            channel = connection.channel()
            channel.queue_declare(queue=QUEUE_NAME, durable=True)
            channel.basic_qos(prefetch_count=1)

            def callback(ch, method, properties, body):  # noqa: ANN001
                process_message(body)
                ch.basic_ack(delivery_tag=method.delivery_tag)

            channel.basic_consume(queue=QUEUE_NAME, on_message_callback=callback)
            logger.info("RabbitMQ consumer started — waiting for messages")
            channel.start_consuming()
        except pika.exceptions.AMQPConnectionError as exc:
            logger.warning("RabbitMQ connection failed: %s — retrying in 5 s", exc)
            time.sleep(5)
        except Exception as exc:  # noqa: BLE001
            logger.error("Consumer error: %s — restarting in 5 s", exc)
            time.sleep(5)


# ── Pydantic Models ───────────────────────────────────────────────────────────
class ManualNotification(BaseModel):
    type: str
    recipient: Optional[str] = None
    payload: dict = {}


# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    init_db()
    t = threading.Thread(target=_rabbitmq_consumer_loop, daemon=True, name="rabbitmq-consumer")
    t.start()
    logger.info("RabbitMQ consumer thread started")


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health_check():
    return {"service": "notification-service", "status": "ok", "version": "1.0.0"}


@app.post("/notify", status_code=201)
def manual_notify(req: ManualNotification):
    """Manually trigger a notification (internal/admin use)."""
    nid = save_notification(req.type, req.recipient, req.payload)
    logger.info("Manual notification sent: %s -> %s", req.type, req.recipient)
    return {"id": nid, "message": "Notification recorded"}


@app.get("/notifications")
def list_notifications():
    """List recent notifications (last 50)."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM notifications ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
    return [dict(r) for r in rows]
