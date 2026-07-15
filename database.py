import logging
import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import declarative_base, sessionmaker

load_dotenv()  # reads a local .env file if present; no-op in production if env vars are set another way

logger = logging.getLogger("threatlens")

# Individual pieces (with local-dev fallbacks) so you don't need every var set just to run locally.
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "threatlens_db")

# DATABASE_URL wins outright if set (e.g. in a hosting platform's env config).
SQLALCHEMY_DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}",
)

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    echo=os.getenv("SQL_ECHO", "false").lower() == "true",
    pool_pre_ping=True,  # drops/replaces dead connections instead of failing on the next query
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_connection() -> bool:
    """
    Call this once at app startup. Fails fast with a specific, readable error
    instead of letting a mysterious OperationalError surface on the first request.
    """
    safe_url = engine.url.render_as_string(hide_password=True)
    try:
        with engine.connect():
            logger.info("Database connection OK (%s)", safe_url)
            return True
    except OperationalError as exc:
        logger.error(
            "Could not connect to database at %s. "
            "Check that: (1) the database server is running, (2) the host/port are correct "
            "(use the service name, not 'localhost', if running in Docker), "
            "(3) the database exists, (4) the user/password are correct, and "
            "(5) pg_hba.conf allows this auth method (Postgres only). Original error: %s",
            safe_url, exc,
        )
        return False