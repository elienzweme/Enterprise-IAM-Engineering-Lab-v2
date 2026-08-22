from app.database import Base, engine
from app.models import models


def initialize_database():
    print("Creating IAM Platform database tables...")
    Base.metadata.create_all(bind=engine)
    print("Database initialization complete.")


if __name__ == "__main__":
    initialize_database()