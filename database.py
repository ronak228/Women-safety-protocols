from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from dotenv import load_dotenv
import os
import time

# Load environment variables
load_dotenv()

# MongoDB Atlas connection string
MONGODB_URI = os.getenv('MONGODB_URI')

# Create MongoDB client with timeout and retry
def get_client():
    max_retries = 3
    retry_delay = 2  # seconds
    
    for attempt in range(max_retries):
        try:
            client = MongoClient(MONGODB_URI, 
                               serverSelectionTimeoutMS=10000,  # Increased timeout
                               connectTimeoutMS=10000,
                               retryWrites=True,
                               retryReads=True)
            # Test the connection
            client.server_info()
            print("Successfully connected to MongoDB!")
            return client
        except Exception as e:
            print(f"Attempt {attempt + 1}/{max_retries} failed: {str(e)}")
            if attempt < max_retries - 1:
                print(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print("Failed to connect to MongoDB after all attempts.")
                return None

# Initialize client and database
client = None
db = None
users = None
volunteers = None
emergency_contacts = None
safety_tips = None

def init_db():
    """Initialize database connection and collections"""
    global client, db, users, volunteers, emergency_contacts, safety_tips
    
    try:
        client = get_client()
        if client is not None:
            db = client.womensafety
            users = db.users
            volunteers = db.volunteers
            emergency_contacts = db.emergency_contacts
            safety_tips = db.safety_tips
            print("Database collections initialized successfully!")
            
            # Add default safety tips if collection is empty
            if safety_tips.count_documents({}) == 0:
                default_tips = [
                    {
                        "title": "Stay Alert",
                        "description": "Always be aware of your surroundings and trust your instincts.",
                        "category": "general"
                    },
                    {
                        "title": "Emergency Contacts",
                        "description": "Keep important emergency numbers saved in your phone.",
                        "category": "preparation"
                    },
                    {
                        "title": "Share Location",
                        "description": "Share your location with trusted friends or family when traveling.",
                        "category": "technology"
                    }
                ]
                safety_tips.insert_many(default_tips)
                print("Default safety tips added successfully!")
        else:
            print("Failed to initialize database connection")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        raise

def get_db():
    """Get database instance"""
    if db is None:
        init_db()  # Try to initialize if not already done
    if db is None:
        raise Exception("Database connection not available")
    return db

def close_db():
    """Close database connection"""
    if client is not None:
        client.close()
        print("Database connection closed")

# Initialize database on module import
init_db() 