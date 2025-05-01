import cv2
import numpy as np
from datetime import datetime, time, timedelta
import logging
import os

class WomenSafetyAnalytics:
    def __init__(self):
        # Initialize logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # Initialize variables for analytics
        self.hotspots = []
        self.alert_history = []
        self.current_frame = None
        self.is_night_time = False

    def load_models(self):
        try:
            # Initialize variables for analytics
            self.hotspots = []
            self.alert_history = []
            self.current_frame = None
            self.is_night_time = False

            self.logger.info("Models loaded successfully")
        except Exception as e:
            self.logger.error(f"Error loading models: {str(e)}")
            raise

    def process_frame(self, frame):
        """
        Process a single frame for analytics features
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

            # Detect SOS gesture
            self.detect_sos_gesture(frame, results)

            # Update hotspots based on alerts
            if results['alerts']:
                self.update_hotspots(results['alerts'])

            return results

        except Exception as e:
            self.logger.error(f"Error processing frame: {str(e)}")
            return None





    def update_time_of_day(self):
        """
        Update whether it's currently night time
        """
        current_time = datetime.now().time()
        self.is_night_time = current_time >= time(20, 0) or current_time <= time(6, 0)





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