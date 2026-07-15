# backend/app/main.py
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import Base, check_db_connection, engine
from .routers import scans

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("threatlens")

app = FastAPI(
    title="ThreatLens API",
    description="Non-intrusive security posture scanning engine.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)


@app.on_event("startup")
def on_startup() -> None:
    """Verify the DB is reachable, then create any missing tables."""
    if not check_db_connection():
        raise RuntimeError(
            "Cannot start ThreatLens: database connection failed. "
            "See the error above for the likely cause."
        )
    logger.info("Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database ready.")


@app.get("/")
def root():
    return {"message": "ThreatLens Backend Running. Database connected!"}