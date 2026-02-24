# init_db.py
from database import engine
from models import Base

def init_db():
    print("Creating database tables...")
    
    # This command looks at your models.py and creates any tables 
    # that do NOT exist in the database yet.
    Base.metadata.create_all(bind=engine)
    
    print("✅ Success! All tables are up to date.")

if __name__ == "__main__":
    init_db()