import os, sqlite3
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, "instance", "app.db")

conn = sqlite3.connect(db_path)
cur = conn.cursor()

hashed_pw = generate_password_hash("attack123")
#print(hashed_pw)
cur.execute("""
    INSERT INTO users (email, password_hash, is_verified)
    VALUES (?, ?, ?)
""", ("hallabol@attack.com", hashed_pw, False))

conn.commit()
conn.close()