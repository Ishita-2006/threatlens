import os

import psycopg2
from dotenv import load_dotenv

load_dotenv()  # looks for a .env file in the current working directory

conn = psycopg2.connect(
    host=os.getenv("DB_HOST", "localhost"),
    port=os.getenv("DB_PORT", "5432"),
    database=os.getenv("DB_NAME", "threatlens_db"),
    user=os.getenv("DB_USER", "postgres"),
    password=os.getenv("DB_PASSWORD", ""),
)

cur = conn.cursor()
cur.execute("SELECT datname FROM pg_database;")
print(cur.fetchall())

conn.close()
print("Connection successful.")