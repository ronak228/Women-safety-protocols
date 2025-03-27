from database import init_db, users
from werkzeug.security import check_password_hash

def list_verified_users():
    try:
        # Initialize database
        init_db()
        
        # Find all verified users
        verified_users = users.find({'is_verified': True})
        
        print("\nVerified Users in Database:")
        print("-" * 50)
        
        for user in verified_users:
            print(f"Name: {user.get('firstName', '')} {user.get('lastName', '')}")
            print(f"Email: {user.get('email', '')}")
            print(f"Phone: {user.get('phone', '')}")
            print("-" * 50)
            
    except Exception as e:
        print(f"Error listing users: {str(e)}")

if __name__ == "__main__":
    list_verified_users() 