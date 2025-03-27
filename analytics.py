import cv2
import numpy as np
from datetime import datetime
import torch
from torchvision.models import detection
from collections import defaultdict
import json
import os
import logging
import mediapipe as mp
from mediapipe.tasks import python
from mediapipe.tasks.python import vision
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/analytics.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class WomenSafetyAnalytics:
    def __init__(self):
        try:
            # Create necessary directories
            os.makedirs('data', exist_ok=True)
            os.makedirs('logs', exist_ok=True)
            
            # Initialize models with error handling
            self.model = None
            self.gender_model = None
            self.gesture_model = None
            
            try:
                # Initialize YOLOv5 model for person detection
                self.model = torch.hub.load('ultralytics/yolov5', 'yolov5s')
                self.model.conf = 0.5  # Default confidence threshold
                logger.info("Successfully loaded YOLOv5 model")
            except Exception as e:
                logger.warning(f"Failed to load YOLOv5 model: {str(e)}")
            
            try:
                # Initialize gender classification model
                self.gender_model = torch.hub.load('pytorch/vision:v0.10.0', 'resnet18', pretrained=True)
                self.gender_model.eval()
                logger.info("Successfully loaded gender classification model")
            except Exception as e:
                logger.warning(f"Failed to load gender classification model: {str(e)}")
            
            try:
                # Initialize MediaPipe for gesture recognition
                self.mp_pose = mp.solutions.pose
                self.pose = self.mp_pose.Pose(
                    min_detection_confidence=0.5,
                    min_tracking_confidence=0.5
                )
                logger.info("Successfully initialized MediaPipe Pose")
            except Exception as e:
                logger.warning(f"Failed to initialize MediaPipe Pose: {str(e)}")
            
            try:
                # Initialize gesture recognition model
                self.gesture_model = torch.hub.load('pytorch/vision:v0.10.0', 'resnet18', pretrained=True)
                self.gesture_model.eval()
                logger.info("Successfully loaded gesture recognition model")
            except Exception as e:
                logger.warning(f"Failed to load gesture recognition model: {str(e)}")
            
            # Store historical data for hotspot analysis
            self.historical_data = defaultdict(list)
            
            # Load hotspot data if exists
            self.hotspot_data = self._load_hotspot_data()
            
            logger.info("Successfully initialized WomenSafetyAnalytics")
        except Exception as e:
            logger.error(f"Error initializing WomenSafetyAnalytics: {str(e)}")
            raise
        
    def _load_hotspot_data(self):
        """Load historical hotspot data from file"""
        try:
            hotspot_file = 'data/hotspot_data.json'
            if os.path.exists(hotspot_file):
                with open(hotspot_file, 'r') as f:
                    return json.load(f)
            return defaultdict(list)
        except Exception as e:
            logger.error(f"Error loading hotspot data: {str(e)}")
            return defaultdict(list)
    
    def _save_hotspot_data(self):
        """Save hotspot data to file"""
        try:
            hotspot_file = 'data/hotspot_data.json'
            with open(hotspot_file, 'w') as f:
                json.dump(self.hotspot_data, f)
        except Exception as e:
            logger.error(f"Error saving hotspot data: {str(e)}")
    
    def detect_persons(self, frame):
        """Detect persons in the frame using YOLOv5"""
        try:
            if self.model is None:
                logger.warning("YOLOv5 model not loaded, skipping person detection")
                return np.array([])
            results = self.model(frame)
            return results.xyxy[0].cpu().numpy()  # Returns bounding boxes and confidence scores
        except Exception as e:
            logger.error(f"Error in person detection: {str(e)}")
            return np.array([])
    
    def classify_gender(self, person_roi):
        """Classify gender of detected person"""
        try:
            if self.gender_model is None:
                logger.warning("Gender classification model not loaded, returning unknown")
                return 'unknown'
            # Preprocess image for gender classification
            person_roi = cv2.resize(person_roi, (224, 224))
            person_roi = torch.from_numpy(person_roi).permute(2, 0, 1).unsqueeze(0).float() / 255.0
            
            with torch.no_grad():
                output = self.gender_model(person_roi)
                gender = 'female' if output.argmax().item() == 0 else 'male'
            
            return gender
        except Exception as e:
            logger.error(f"Error in gender classification: {str(e)}")
            return 'unknown'
    
    def detect_sos_gesture(self, frame):
        """Detect SOS gestures using MediaPipe Pose"""
        try:
            if not hasattr(self, 'pose'):
                logger.warning("MediaPipe Pose not initialized, skipping gesture detection")
                return False
            # Convert BGR to RGB
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            
            # Process the frame
            results = self.pose.process(frame_rgb)
            
            if not results.pose_landmarks:
                return False
            
            # Get hand landmarks
            left_hand = results.pose_landmarks.landmark[self.mp_pose.PoseLandmark.LEFT_WRIST]
            right_hand = results.pose_landmarks.landmark[self.mp_pose.PoseLandmark.RIGHT_WRIST]
            
            # Check for SOS gesture pattern
            if (left_hand.y < 0.5 and right_hand.y < 0.5 and  # Hands raised
                abs(left_hand.x - right_hand.x) > 0.3):  # Hands spread apart
                return True
            
            return False
        except Exception as e:
            logger.error(f"Error in SOS gesture detection: {str(e)}")
            return False
    
    def analyze_scene(self, frame, timestamp):
        """Analyze the scene for potential threats"""
        try:
            # Detect persons
            detections = self.detect_persons(frame)
            
            # Initialize counters
            men_count = 0
            women_count = 0
            alerts = []
            
            # Process each detection
            for det in detections:
                try:
                    x1, y1, x2, y2, conf, cls = det
                    person_roi = frame[int(y1):int(y2), int(x1):int(x2)]
                    
                    # Classify gender
                    gender = self.classify_gender(person_roi)
                    
                    if gender == 'male':
                        men_count += 1
                    elif gender == 'female':
                        women_count += 1
                except Exception as e:
                    logger.error(f"Error processing detection: {str(e)}")
                    continue
            
            # Check for potential threats
            current_hour = timestamp.hour
            
            # Lone woman at night detection
            if current_hour >= 20 or current_hour <= 5:  # Night time (8 PM to 5 AM)
                if women_count == 1 and men_count > 0:
                    alerts.append({
                        'type': 'lone_woman_night',
                        'severity': 'high',
                        'message': 'Lone woman detected at night with men present'
                    })
            
            # Woman surrounded by men detection
            if women_count == 1 and men_count >= 3:
                alerts.append({
                    'type': 'woman_surrounded',
                    'severity': 'medium',
                    'message': 'Woman surrounded by multiple men'
                })
            
            # Detect SOS gesture
            sos_detected = self.detect_sos_gesture(frame)
            if sos_detected:
                alerts.append({
                    'type': 'sos_gesture',
                    'severity': 'high',
                    'message': 'SOS gesture detected'
                })
            
            # Update historical data
            self.historical_data[timestamp.strftime('%Y-%m-%d')].append({
                'timestamp': timestamp.isoformat(),
                'men_count': men_count,
                'women_count': women_count,
                'alerts': alerts
            })
            
            # Analyze hotspots
            self._update_hotspots(timestamp, alerts)
            
            return {
                'men_count': men_count,
                'women_count': women_count,
                'alerts': alerts,
                'gender_distribution': {
                    'men': men_count,
                    'women': women_count
                },
                'sos_detected': sos_detected,
                'is_night_time': current_hour >= 20 or current_hour <= 5
            }
        except Exception as e:
            logger.error(f"Error in scene analysis: {str(e)}")
            return {
                'men_count': 0,
                'women_count': 0,
                'alerts': [],
                'gender_distribution': {
                    'men': 0,
                    'women': 0
                },
                'sos_detected': False,
                'is_night_time': False
            }
    
    def _update_hotspots(self, timestamp, alerts):
        """Update hotspot data based on alerts"""
        try:
            if alerts:
                location_key = timestamp.strftime('%Y-%m-%d-%H')
                self.hotspot_data[location_key].extend(alerts)
                self._save_hotspot_data()
        except Exception as e:
            logger.error(f"Error updating hotspots: {str(e)}")
    
    def get_hotspots(self):
        """Get identified hotspots based on historical data"""
        try:
            hotspot_scores = defaultdict(int)
            
            for location, alerts in self.hotspot_data.items():
                for alert in alerts:
                    if alert['severity'] == 'high':
                        hotspot_scores[location] += 3
                    elif alert['severity'] == 'medium':
                        hotspot_scores[location] += 2
                    else:
                        hotspot_scores[location] += 1
            
            # Sort hotspots by score
            sorted_hotspots = sorted(hotspot_scores.items(), key=lambda x: x[1], reverse=True)
            return sorted_hotspots[:10]  # Return top 10 hotspots
        except Exception as e:
            logger.error(f"Error getting hotspots: {str(e)}")
            return []
    
    def process_frame(self, frame):
        """Process a single frame and return analysis results"""
        try:
            timestamp = datetime.now()
            analysis = self.analyze_scene(frame, timestamp)
            return analysis
        except Exception as e:
            logger.error(f"Error processing frame: {str(e)}")
            return {
                'men_count': 0,
                'women_count': 0,
                'alerts': [],
                'gender_distribution': {
                    'men': 0,
                    'women': 0
                },
                'sos_detected': False,
                'is_night_time': False
            } 