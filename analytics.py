import cv2
import numpy as np
from datetime import datetime
import torch
from torchvision.models import detection
from collections import defaultdict
import json
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WomenSafetyAnalytics:
    def __init__(self):
        try:
            # Initialize YOLOv5 model for person detection
            self.model = torch.hub.load('ultralytics/yolov5', 'yolov5s')
            self.model.conf = 0.5  # Confidence threshold
            
            # Initialize gender classification model
            self.gender_model = torch.hub.load('pytorch/vision:v0.10.0', 'resnet18', pretrained=True)
            self.gender_model.eval()
            
            # Initialize gesture recognition model
            self.gesture_model = torch.hub.load('pytorch/vision:v0.10.0', 'resnet18', pretrained=True)
            self.gesture_model.eval()
            
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
            if os.path.exists('hotspot_data.json'):
                with open('hotspot_data.json', 'r') as f:
                    return json.load(f)
            return defaultdict(list)
        except Exception as e:
            logger.error(f"Error loading hotspot data: {str(e)}")
            return defaultdict(list)
    
    def _save_hotspot_data(self):
        """Save hotspot data to file"""
        try:
            with open('hotspot_data.json', 'w') as f:
                json.dump(self.hotspot_data, f)
        except Exception as e:
            logger.error(f"Error saving hotspot data: {str(e)}")
    
    def detect_persons(self, frame):
        """Detect persons in the frame using YOLOv5"""
        try:
            results = self.model(frame)
            return results.xyxy[0].cpu().numpy()  # Returns bounding boxes and confidence scores
        except Exception as e:
            logger.error(f"Error in person detection: {str(e)}")
            return np.array([])
    
    def classify_gender(self, person_roi):
        """Classify gender of detected person"""
        try:
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
                }
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
                }
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
    
    def detect_sos_gesture(self, frame):
        """Detect SOS gestures using pose estimation"""
        try:
            # This is a placeholder for SOS gesture detection
            # In a real implementation, you would use a pose estimation model
            # like MediaPipe or OpenPose to detect specific hand gestures
            return False
        except Exception as e:
            logger.error(f"Error in SOS gesture detection: {str(e)}")
            return False
    
    def process_frame(self, frame):
        """Process a single frame and return analysis results"""
        try:
            timestamp = datetime.now()
            analysis = self.analyze_scene(frame, timestamp)
            
            # Add SOS gesture detection
            if self.detect_sos_gesture(frame):
                analysis['alerts'].append({
                    'type': 'sos_gesture',
                    'severity': 'high',
                    'message': 'SOS gesture detected'
                })
            
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
                }
            } 