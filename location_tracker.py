from datetime import datetime, timedelta
import json
from geopy.geocoders import Nominatim
from geopy.distance import geodesic
import logging
from database import get_db
from bson import ObjectId

# Try to import analytics module, but don't fail if it's not available
try:
    from analytics.safety_analytics import WomenSafetyAnalytics
    has_analytics = True
except ImportError:
    print("Warning: Analytics module not available in LocationTracker. Analytics features will be disabled.")
    has_analytics = False

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LocationTracker:
    def __init__(self, db):
        self.geolocator = Nominatim(user_agent="women_safety_app")
        self.db = db
        self.locations = db.user_locations
        self.location_history = self.db.location_history
        self.backup_locations = self.db.backup_locations
        if has_analytics:
            self.analytics = WomenSafetyAnalytics()
        else:
            self.analytics = None
        
    def save_location(self, user_id, latitude, longitude, timestamp=None):
        """Save user's current location with backup"""
        try:
            if timestamp is None:
                timestamp = datetime.now()
                
            # Get address from coordinates
            location = self.geolocator.reverse((latitude, longitude))
            address = location.address if location else "Unknown location"
            
            # Create location document
            location_data = {
                'user_id': user_id,
                'latitude': latitude,
                'longitude': longitude,
                'address': address,
                'timestamp': timestamp,
                'is_backup': False
            }
            
            # Save to primary location history
            self.location_history.insert_one(location_data)
            
            # Save to backup collection
            location_data['is_backup'] = True
            self.backup_locations.insert_one(location_data)
            
            logger.info(f"Location saved for user {user_id} at {address}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving location: {str(e)}")
            return False
            
    def get_user_location_history(self, user_id, limit=50):
        """Get user's location history"""
        try:
            history = list(self.location_history.find(
                {'user_id': user_id}
            ).sort('timestamp', -1).limit(limit))
            
            return [{
                'latitude': loc['latitude'],
                'longitude': loc['longitude'],
                'timestamp': loc['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            } for loc in history]
        except Exception as e:
            logger.error(f"Error getting location history: {str(e)}")
            return []
            
    def get_backup_locations(self, user_id, limit=10):
        """Get user's backup locations"""
        try:
            backup_locs = list(self.backup_locations.find(
                {'user_id': user_id, 'is_backup': True}
            ).sort('timestamp', -1).limit(limit))
            
            return backup_locs
        except Exception as e:
            logger.error(f"Error getting backup locations: {str(e)}")
            return []
            
    def calculate_distance(self, loc1, loc2):
        """Calculate distance between two locations in kilometers"""
        try:
            point1 = (loc1['latitude'], loc1['longitude'])
            point2 = (loc2['latitude'], loc2['longitude'])
            return geodesic(point1, point2).kilometers
        except Exception as e:
            logger.error(f"Error calculating distance: {str(e)}")
            return 0
            
    def get_nearby_users(self, latitude, longitude, radius_km=5):
        """Find users within specified radius"""
        try:
            current_time = datetime.now()
            # Get recent locations within last hour
            recent_locations = self.location_history.find({
                'timestamp': {'$gte': current_time - timedelta(hours=1)}
            })
            
            nearby_users = []
            current_point = (latitude, longitude)
            
            for loc in recent_locations:
                loc_point = (loc['latitude'], loc['longitude'])
                distance = geodesic(current_point, loc_point).kilometers
                
                if distance <= radius_km:
                    nearby_users.append({
                        'user_id': loc['user_id'],
                        'distance': distance,
                        'location': loc_point
                    })
                    
            return sorted(nearby_users, key=lambda x: x['distance'])
            
        except Exception as e:
            logger.error(f"Error finding nearby users: {str(e)}")
            return []
            
    def export_location_history(self, user_id, start_date=None, end_date=None):
        """Export user's location history within date range"""
        try:
            query = {'user_id': user_id}
            if start_date or end_date:
                query['timestamp'] = {}
                if start_date:
                    query['timestamp']['$gte'] = start_date
                if end_date:
                    query['timestamp']['$lte'] = end_date
                    
            history = list(self.location_history.find(query).sort('timestamp', 1))
            
            return [{
                'latitude': loc['latitude'],
                'longitude': loc['longitude'],
                'timestamp': loc['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            } for loc in history]
        except Exception as e:
            logger.error(f"Error exporting location history: {str(e)}")
            return []
            
    def update_user_location(self, user_id, latitude, longitude):
        """Update user's location with timestamp"""
        try:
            location_data = {
                'user_id': user_id,
                'latitude': float(latitude),
                'longitude': float(longitude),
                'timestamp': datetime.utcnow()
            }
            self.locations.insert_one(location_data)
            return True
        except Exception as e:
            print(f"Error updating location: {str(e)}")
            return False

    def get_recent_locations(self, user_id, hours=3):
        """Get user's locations from the past specified hours"""
        try:
            three_hours_ago = datetime.utcnow() - timedelta(hours=hours)
            recent_locations = self.locations.find({
                'user_id': user_id,
                'timestamp': {'$gte': three_hours_ago}
            }).sort('timestamp', -1)
            
            return [{
                'latitude': loc['latitude'],
                'longitude': loc['longitude'],
                'timestamp': loc['timestamp']
            } for loc in recent_locations]
        except Exception as e:
            print(f"Error getting recent locations: {str(e)}")
            return []

    def get_current_location(self, user_id):
        """Get user's most recent location"""
        try:
            latest_location = self.locations.find_one(
                {'user_id': user_id},
                sort=[('timestamp', -1)]
            )
            if latest_location:
                return {
                    'latitude': latest_location['latitude'],
                    'longitude': latest_location['longitude'],
                    'timestamp': latest_location['timestamp']
                }
            return None
        except Exception as e:
            print(f"Error getting current location: {str(e)}")
            return None 