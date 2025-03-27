from backup_restore import create_backup, list_backups
from database import init_db

def test_backup():
    print("Testing backup functionality...")
    
    # Ensure database is initialized
    init_db()
    
    # Create a backup
    success, result = create_backup()
    if success:
        print(f"Backup created successfully: {result}")
    else:
        print(f"Backup failed: {result}")
    
    # List all backups
    backups = list_backups()
    print("\nAvailable backups:")
    for backup in backups:
        print(f"- {backup['filename']} (Created: {backup['created_at']})")

if __name__ == "__main__":
    test_backup() 