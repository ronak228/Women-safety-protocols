import os
import json
from datetime import datetime
from database import users, volunteers, emergency_contacts, safety_tips, get_db, init_db

# Define backup directory relative to the current file
BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')

def ensure_backup_dir():
    """Ensure backup directory exists with proper permissions"""
    try:
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR, exist_ok=True)
            print(f"Created backup directory at: {BACKUP_DIR}")
        return True
    except Exception as e:
        print(f"Error creating backup directory: {str(e)}")
        return False

def create_backup():
    """Create a backup of all collections"""
    try:
        # Ensure database connection
        db = get_db()
        if db is None:
            init_db()  # Try to initialize if not already done
            db = get_db()
            if db is None:
                return False, "Failed to connect to database"
            
        if not ensure_backup_dir():
            return False, "Failed to create backup directory"
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(BACKUP_DIR, f'backup_{timestamp}.json')
        
        # Get data from collections
        backup_data = {}
        
        # Safely get data from each collection
        try:
            backup_data['users'] = list(users.find({}, {'_id': 0}))
            print(f"Backed up {len(backup_data['users'])} users")
        except Exception as e:
            print(f"Error backing up users: {str(e)}")
            backup_data['users'] = []
            
        try:
            backup_data['volunteers'] = list(volunteers.find({}, {'_id': 0}))
            print(f"Backed up {len(backup_data['volunteers'])} volunteers")
        except Exception as e:
            print(f"Error backing up volunteers: {str(e)}")
            backup_data['volunteers'] = []
            
        try:
            backup_data['emergency_contacts'] = list(emergency_contacts.find({}, {'_id': 0}))
            print(f"Backed up {len(backup_data['emergency_contacts'])} emergency contacts")
        except Exception as e:
            print(f"Error backing up emergency contacts: {str(e)}")
            backup_data['emergency_contacts'] = []
            
        try:
            backup_data['safety_tips'] = list(safety_tips.find({}, {'_id': 0}))
            print(f"Backed up {len(backup_data['safety_tips'])} safety tips")
        except Exception as e:
            print(f"Error backing up safety tips: {str(e)}")
            backup_data['safety_tips'] = []
        
        # Write backup file
        with open(backup_file, 'w', encoding='utf-8') as f:
            json.dump(backup_data, f, indent=2, default=str)
            
        print(f"Backup created successfully at: {backup_file}")
        return True, backup_file
    except Exception as e:
        print(f"Backup error: {str(e)}")
        return False, str(e)

def restore_backup(backup_file):
    """Restore data from a backup file"""
    try:
        # Ensure database connection
        db = get_db()
        if db is None:
            init_db()  # Try to initialize if not already done
            db = get_db()
            if db is None:
                return False, "Failed to connect to database"
            
        if not os.path.exists(backup_file):
            return False, "Backup file not found"
            
        with open(backup_file, 'r', encoding='utf-8') as f:
            backup_data = json.load(f)
            
        # Clear existing data
        try:
            users.delete_many({})
            volunteers.delete_many({})
            emergency_contacts.delete_many({})
            safety_tips.delete_many({})
            print("Cleared existing data successfully")
        except Exception as e:
            print(f"Error clearing existing data: {str(e)}")
            return False, f"Failed to clear existing data: {str(e)}"
        
        # Restore data
        try:
            if backup_data.get('users'):
                users.insert_many(backup_data['users'])
                print(f"Restored {len(backup_data['users'])} users")
            if backup_data.get('volunteers'):
                volunteers.insert_many(backup_data['volunteers'])
                print(f"Restored {len(backup_data['volunteers'])} volunteers")
            if backup_data.get('emergency_contacts'):
                emergency_contacts.insert_many(backup_data['emergency_contacts'])
                print(f"Restored {len(backup_data['emergency_contacts'])} emergency contacts")
            if backup_data.get('safety_tips'):
                safety_tips.insert_many(backup_data['safety_tips'])
                print(f"Restored {len(backup_data['safety_tips'])} safety tips")
        except Exception as e:
            print(f"Error restoring data: {str(e)}")
            return False, f"Failed to restore data: {str(e)}"
            
        print(f"Backup restored successfully from: {backup_file}")
        return True, "Backup restored successfully"
    except Exception as e:
        print(f"Restore error: {str(e)}")
        return False, str(e)

def list_backups():
    """List all available backups"""
    try:
        if not ensure_backup_dir():
            return []
            
        backups = []
        for filename in os.listdir(BACKUP_DIR):
            if filename.startswith('backup_') and filename.endswith('.json'):
                file_path = os.path.join(BACKUP_DIR, filename)
                file_stats = os.stat(file_path)
                backups.append({
                    'filename': filename,
                    'path': file_path,
                    'size': file_stats.st_size,
                    'created_at': datetime.fromtimestamp(file_stats.st_ctime)
                })
        return sorted(backups, key=lambda x: x['created_at'], reverse=True)
    except Exception as e:
        print(f"Error listing backups: {str(e)}")
        return [] 