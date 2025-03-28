import cv2
import numpy as np
import tensorflow as tf
from datetime import datetime, time, timedelta
import mediapipe as mp
from sklearn.cluster import DBSCAN
import logging
import os

class WomenSafetyAnalytics:
    def __init__(self):
        # Initialize logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # Load pre-trained models
        self.load_models()

        # Initialize MediaPipe for pose detection
        self.mp_pose = mp.solutions.pose
        self.pose = self.mp_pose.Pose(
            min_detection_confidence=0.5,
            min_tracking_confidence=0.5
        )

        # Initialize variables for analytics
        self.hotspots = []
        self.alert_history = []
        self.current_frame = None
        self.is_night_time = False

    def load_models(self):
        try:
            # Load gender classification model
            model_path = os.path.join(os.path.dirname(__file__), 'models/gender_classification_model')
            self.gender_model = tf.keras.models.load_model(model_path)

            # Load person detection model (using YOLOv4 or similar)
            weights_path = os.path.join(os.path.dirname(__file__), 'models/yolov4.weights')
            config_path = os.path.join(os.path.dirname(__file__), 'models/yolov4.cfg')
            self.person_detection_net = cv2.dnn.readNet(weights_path, config_path)

            self.logger.info("Models loaded successfully")
        except Exception as e:
            self.logger.error(f"Error loading models: {str(e)}")
            raise

    def process_frame(self, frame):
        """
        Process a single frame for all analytics features
        """
        try:
            self.current_frame = frame
            results = {
                'timestamp': datetime.now(),
                'alerts': [],
                'statistics': {}
            }

            # Update time of day
            self.update_time_of_day()

            # Detect people and their genders
            people = self.detect_people(frame)
            gender_distribution = self.classify_genders(people)

            # Update statistics
            results['statistics'] = {
                'total_people': len(people),
                'men_count': gender_distribution['men'],
                'women_count': gender_distribution['women']
            }

            # Check for various scenarios
            self.check_lone_woman(people, results)
            self.check_woman_surrounded(people, results)
            self.detect_sos_gesture(frame, results)

            # Update hotspots based on alerts
            if results['alerts']:
                self.update_hotspots(results['alerts'])

            return results

        except Exception as e:
            self.logger.error(f"Error processing frame: {str(e)}")
            return None

    def detect_people(self, frame):
        """
        Detect people in the frame using YOLOv4
        """
        try:
            height, width = frame.shape[:2]
            blob = cv2.dnn.blobFromImage(frame, 1/255.0, (416, 416), swapRB=True, crop=False)
            self.person_detection_net.setInput(blob)
            
            layer_names = self.person_detection_net.getLayerNames()
            output_layers = [layer_names[i - 1] for i in self.person_detection_net.getUnconnectedOutLayers()]
            outputs = self.person_detection_net.forward(output_layers)

            people = []
            for output in outputs:
                for detection in output:
                    scores = detection[5:]
                    class_id = np.argmax(scores)
                    confidence = scores[class_id]

                    if confidence > 0.5 and class_id == 0:  # class 0 is person in COCO dataset
                        center_x = int(detection[0] * width)
                        center_y = int(detection[1] * height)
                        w = int(detection[2] * width)
                        h = int(detection[3] * height)

                        x = int(center_x - w/2)
                        y = int(center_y - h/2)

                        people.append({
                            'bbox': (x, y, w, h),
                            'confidence': float(confidence),
                            'center': (center_x, center_y)
                        })

            return people

        except Exception as e:
            self.logger.error(f"Error detecting people: {str(e)}")
            return []

    def classify_genders(self, people):
        """
        Classify gender for each detected person
        """
        try:
            men_count = 0
            women_count = 0

            for person in people:
                x, y, w, h = person['bbox']
                if x >= 0 and y >= 0 and x + w <= self.current_frame.shape[1] and y + h <= self.current_frame.shape[0]:
                    roi = self.current_frame[y:y+h, x:x+w]
                    if roi.size > 0:
                        # Preprocess for gender classification
                        roi = cv2.resize(roi, (64, 64))
                        roi = roi.astype('float32') / 255.0
                        roi = np.expand_dims(roi, axis=0)

                        # Predict gender
                        prediction = self.gender_model.predict(roi)
                        person['gender'] = 'woman' if prediction[0][0] > 0.5 else 'man'
                        
                        if person['gender'] == 'woman':
                            women_count += 1
                        else:
                            men_count += 1

            return {'men': men_count, 'women': women_count}

        except Exception as e:
            self.logger.error(f"Error classifying genders: {str(e)}")
            return {'men': 0, 'women': 0}

    def update_time_of_day(self):
        """
        Update whether it's currently night time
        """
        current_time = datetime.now().time()
        self.is_night_time = current_time >= time(20, 0) or current_time <= time(6, 0)

    def check_lone_woman(self, people, results):
        """
        Check for lone women, especially at night
        """
        try:
            women = [p for p in people if p.get('gender') == 'woman']
            men = [p for p in people if p.get('gender') == 'man']

            for woman in women:
                nearby_people = 0
                woman_center = woman['center']

                for person in people:
                    if person != woman:
                        distance = np.sqrt(
                            (woman_center[0] - person['center'][0])**2 +
                            (woman_center[1] - person['center'][1])**2
                        )
                        if distance < 200:  # Threshold distance in pixels
                            nearby_people += 1

                if nearby_people == 0 and self.is_night_time:
                    results['alerts'].append({
                        'type': 'lone_woman',
                        'location': woman_center,
                        'severity': 'medium',
                        'message': 'Lone woman detected at night'
                    })

        except Exception as e:
            self.logger.error(f"Error checking for lone woman: {str(e)}")

    def check_woman_surrounded(self, people, results):
        """
        Check for women surrounded by men
        """
        try:
            women = [p for p in people if p.get('gender') == 'woman']
            men = [p for p in people if p.get('gender') == 'man']

            for woman in women:
                surrounding_men = 0
                woman_center = woman['center']

                for man in men:
                    distance = np.sqrt(
                        (woman_center[0] - man['center'][0])**2 +
                        (woman_center[1] - man['center'][1])**2
                    )
                    if distance < 150:  # Threshold distance in pixels
                        surrounding_men += 1

                if surrounding_men >= 3:  # Threshold number of surrounding men
                    results['alerts'].append({
                        'type': 'surrounded',
                        'location': woman_center,
                        'severity': 'high',
                        'message': f'Woman surrounded by {surrounding_men} men'
                    })

        except Exception as e:
            self.logger.error(f"Error checking for surrounded woman: {str(e)}")

    def detect_sos_gesture(self, frame, results):
        """
        Detect SOS gestures using MediaPipe Pose
        """
        try:
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            pose_results = self.pose.process(frame_rgb)

            if pose_results.pose_landmarks:
                landmarks = pose_results.pose_landmarks.landmark

                # Check for raised hands (SOS gesture)
                if (landmarks[self.mp_pose.PoseLandmark.LEFT_WRIST].y < 
                    landmarks[self.mp_pose.PoseLandmark.LEFT_SHOULDER].y and
                    landmarks[self.mp_pose.PoseLandmark.RIGHT_WRIST].y < 
                    landmarks[self.mp_pose.PoseLandmark.RIGHT_SHOULDER].y):
                    
                    results['alerts'].append({
                        'type': 'sos_gesture',
                        'location': (
                            int(landmarks[self.mp_pose.PoseLandmark.NOSE].x * frame.shape[1]),
                            int(landmarks[self.mp_pose.PoseLandmark.NOSE].y * frame.shape[0])
                        ),
                        'severity': 'high',
                        'message': 'SOS gesture detected'
                    })

        except Exception as e:
            self.logger.error(f"Error detecting SOS gesture: {str(e)}")

    def update_hotspots(self, alerts):
        """
        Update hotspots based on alerts
        """
        try:
            # Add new alert locations
            new_locations = [(alert['location'][0], alert['location'][1]) for alert in alerts]
            self.alert_history.extend(new_locations)

            # Keep only recent history (last 24 hours)
            recent_cutoff = datetime.now() - timedelta(hours=24)
            self.alert_history = [loc for loc, time in self.alert_history 
                                if time > recent_cutoff]

            # Cluster alert locations to identify hotspots
            if len(self.alert_history) >= 5:
                clustering = DBSCAN(eps=100, min_samples=3).fit(self.alert_history)
                
                # Update hotspots
                self.hotspots = []
                for label in set(clustering.labels_):
                    if label != -1:  # Ignore noise points
                        cluster_points = np.array([point for i, point 
                                                in enumerate(self.alert_history) 
                                                if clustering.labels_[i] == label])
                        center = np.mean(cluster_points, axis=0)
                        self.hotspots.append({
                            'location': tuple(center),
                            'intensity': len(cluster_points)
                        })

        except Exception as e:
            self.logger.error(f"Error updating hotspots: {str(e)}")

    def get_hotspots(self):
        """
        Get current hotspots
        """
        return self.hotspots

    def get_statistics(self):
        """
        Get current statistics
        """
        return {
            'total_alerts': len(self.alert_history),
            'hotspots_count': len(self.hotspots),
            'current_time_status': 'night' if self.is_night_time else 'day'
        } 