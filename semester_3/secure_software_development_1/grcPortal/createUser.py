import os, sqlite3
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, "instance", "app.db")

conn = sqlite3.connect(db_path)
cur = conn.cursor()

hashed_pw = generate_password_hash("Sksf@1234")
print(hashed_pw)
cur.execute("""
    INSERT INTO users (email, password_hash, is_verified)
    VALUES (?, ?, ?)
""", ("kush786srj@gmail.com", hashed_pw, 1))

conn.commit()
conn.close()