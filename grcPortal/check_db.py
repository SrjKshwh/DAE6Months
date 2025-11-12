from app import create_app
from db import get_session
from sqlalchemy import text

app = create_app()
app.app_context().push()

db = get_session()
print('Database tables:')
result = db.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
for row in result:
    print(f'  {row[0]}')

# Check alerts table schema
print('\nAlerts table schema:')
result = db.execute(text("PRAGMA table_info(alerts)"))
for row in result:
    print(f'  {row[1]}: {row[2]}')

db.close()