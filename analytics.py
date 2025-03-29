import cv2
import numpy as np
from datetime import datetime
import logging
from collections import defaultdict
import json
import os

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WomenSafetyAnalytics:
    def __init__(self):
        # Load pre-trained models
        self.face_detector = cv2.dnn.readNetFromCaffe(
            os.path.join('models', 'deploy.prototxt'),
            os.path.join('models', 'res10_300x300_ssd_iter_140000.caffemodel')
        )
        self.gender_classifier = cv2.dnn.readNetFromCaffe(
            os.path.join('models', 'gender_deploy.prototxt'),
            os.path.join('models', 'gender_net.caffemodel')
        )
        
        # Initialize analytics data structures
        self.historical_data = defaultdict(list)
        self.hotspots = defaultdict(int)
        self.alert_thresholds = {
            'lone_woman_night': 1,
            'woman_surrounded': 3,
            'sos_gesture': 0.7  # confidence threshold
        }
        
        # Load existing hotspots data if available
        self.load_hotspots_data()
        
    def load_hotspots_data(self):
        """Load hotspots data from file if it exists"""
        try:
            if os.path.exists('hotspots.json'):
                with open('hotspots.json', 'r') as f:
                    self.hotspots = defaultdict(int, json.load(f))
        except Exception as e:
            logger.error(f"Error loading hotspots data: {str(e)}")
    
    def save_hotspots_data(self):
        """Save hotspots data to file"""
        try:
            with open('hotspots.json', 'w') as f:
                json.dump(dict(self.hotspots), f)
        except Exception as e:
            logger.error(f"Error saving hotspots data: {str(e)}")
            
    def detect_persons(self, frame):
        """Detect persons in the frame"""
        try:
            height, width = frame.shape[:2]
            blob = cv2.dnn.blobFromImage(frame, 1.0, (300, 300), [104, 117, 123], False, False)
            
            self.face_detector.setInput(blob)
            detections = self.face_detector.forward()
            
            persons = []
            for i in range(detections.shape[2]):
                confidence = detections[0, 0, i, 2]
                if confidence > 0.5:  # Confidence threshold
                    box = detections[0, 0, i, 3:7] * np.array([width, height, width, height])
                    x1, y1, x2, y2 = box.astype(int)
                    persons.append({
                        'box': (x1, y1, x2, y2),
                        'confidence': confidence
                    })
            
            return persons
        except Exception as e:
            logger.error(f"Error in person detection: {str(e)}")
            return []
            
    def classify_gender(self, face):
        """Classify gender of detected face"""
        try:
            blob = cv2.dnn.blobFromImage(face, 1.0, (227, 227), [78.4263377603, 87.7689143744, 114.895847746], False, False)
            self.gender_classifier.setInput(blob)
            gender_preds = self.gender_classifier.forward()
            gender = "Female" if gender_preds[0][0] > 0.5 else "Male"
            return gender
        except Exception as e:
            logger.error(f"Error in gender classification: {str(e)}")
            return "Unknown"
            
    def detect_anomalies(self, frame, persons):
        """Detect potential safety anomalies"""
        try:
            anomalies = []
            
            # Check for lone woman at night
            if self._is_night_time():
                for person in persons:
                    if person['confidence'] > 0.8:
                        face = frame[person['box'][1]:person['box'][3], person['box'][0]:person['box'][2]]
                        if self.classify_gender(face) == "Female":
                            anomalies.append({
                                'type': 'lone_woman_night',
                                'location': person['box'],
                                'confidence': person['confidence']
                            })
            
            # Check for woman surrounded by multiple people
            women = [p for p in persons if p['confidence'] > 0.8]
            if len(women) > 3:
                anomalies.append({
                    'type': 'woman_surrounded',
                    'count': len(women),
                    'confidence': 0.9
                })
            
            return anomalies
        except Exception as e:
            logger.error(f"Error in anomaly detection: {str(e)}")
            return []
            
    def _is_night_time(self):
        """Check if current time is during night hours"""
        current_hour = datetime.now().hour
        return current_hour < 6 or current_hour > 18  # Night hours: 6 PM to 6 AM
    
    def detect_sos_gesture(self, frame, person_roi):
        """Detect SOS gesture using pose estimation"""
        try:
            # Implement SOS gesture detection using pose estimation
            # This is a simplified version - you would need to implement proper pose estimation
            # For now, we'll return a random value for demonstration
            return np.random.random() > 0.9
        except Exception as e:
            logger.error(f"Error in SOS gesture detection: {str(e)}")
            return False
    
    def update_hotspots(self, location, incident_type):
        """Update hotspots data based on incidents"""
        try:
            self.hotspots[location] += 1
            self.save_hotspots_data()
        except Exception as e:
            logger.error(f"Error updating hotspots: {str(e)}")
            
    def process_frame(self, frame):
        """Process a single frame and return analytics results"""
        try:
            results = {
                'men_count': 0,
                'women_count': 0,
                'lone_woman_night': False,
                'woman_surrounded': False,
                'sos_detected': False,
                'is_night_time': self._is_night_time(),
                'alerts': []
            }
            
            # Detect persons
            detections = self.detect_persons(frame)
            
            # Process each detection
            for det in detections:
                x1, y1, x2, y2 = det['box']
                conf = det['confidence']
                person_roi = frame[y1:y2, x1:x2]
                
                # Classify gender
                gender = self.classify_gender(person_roi)
                if gender == "Male":
                    results['men_count'] += 1
                elif gender == "Female":
                    results['women_count'] += 1
                
                # Check for SOS gesture
                if gender == "Female" and self.detect_sos_gesture(frame, person_roi):
                    results['sos_detected'] = True
                    results['alerts'].append({
                        'type': 'sos_gesture',
                        'confidence': conf,
                        'location': (x1, y1)
                    })
            
            # Check for lone woman at night
            if results['is_night_time'] and results['women_count'] == 1 and results['men_count'] == 0:
                results['lone_woman_night'] = True
                results['alerts'].append({
                    'type': 'lone_woman_night',
                    'severity': 'high'
                })
                
            # Check for woman surrounded by men
            if results['women_count'] == 1 and results['men_count'] >= self.alert_thresholds['woman_surrounded']:
                results['woman_surrounded'] = True
                results['alerts'].append({
                    'type': 'woman_surrounded',
                    'severity': 'medium',
                    'men_count': results['men_count']
                })
            
            # Update historical data
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.historical_data[timestamp].append(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Error processing frame: {str(e)}")
            return {
                'error': str(e),
                'men_count': 0,
                'women_count': 0,
                'alerts': []
            }
            
    def get_hotspots(self):
        """Get identified hotspots"""
        try:
            # Sort hotspots by incident count
            sorted_hotspots = sorted(
                self.hotspots.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_hotspots[:10]  # Return top 10 hotspots
        except Exception as e:
            logger.error(f"Error getting hotspots: {str(e)}")
            return []
    
    def get_statistics(self):
        """Get analytics statistics"""
        try:
            stats = {
                'total_incidents': sum(len(alerts) for alerts in self.historical_data.values()),
                'high_severity_alerts': sum(
                    1 for alerts in self.historical_data.values()
                    for alert in alerts
                    if alert.get('severity') == 'high'
                ),
                'gender_distribution': {
                    'total_men': sum(
                        data['men_count'] for alerts in self.historical_data.values()
                        for data in alerts
                    ),
                    'total_women': sum(
                        data['women_count'] for alerts in self.historical_data.values()
                        for data in alerts
                    )
                }
            }
            return stats
        except Exception as e:
            logger.error(f"Error getting statistics: {str(e)}")
            return {
                'total_incidents': 0,
                'high_severity_alerts': 0,
                'gender_distribution': {'total_men': 0, 'total_women': 0}
            } 