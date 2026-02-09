from sqlalchemy import text
from database import engine

print("Updating database schema...")

try:
    with engine.connect() as conn:
        # Check if column exists is complex, so we use a try/except block
        # This adds the column and creates the foreign key relationship
        conn.execute(text("ALTER TABLE domains ADD COLUMN user_id INTEGER REFERENCES users(id);"))
        conn.commit()
        print("✅ Success! Column 'user_id' added to 'domains' table.")
except Exception as e:
    # If it fails, it might be because the column already exists, which is fine.
    print(f"⚠️ Info: {e}")
    print("If the error says 'column already exists', you are safe to proceed.")

print("Done.")