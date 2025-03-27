from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file
from database import init_db, get_db, close_db, users, volunteers, emergency_contacts, safety_tips
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from twilio.rest import Client
from dotenv import load_dotenv
import re
import random
import string
from flask_mail import Mail, Message
from backup_restore import create_backup, restore_backup, list_backups
from sso import get_google_auth_url, handle_google_callback
from analytics import WomenSafetyAnalytics
import cv2
import numpy as np
from PIL import Image
import io
load_dotenv()


# ronak

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('EMAIL_USER')

mail = Mail(app)

# Validation functions
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_phone(phone):
    phone = re.sub(r'\D', '', phone)
    return len(phone) == 10

def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True

def validate_name(name):
    return bool(re.match(r'^[a-zA-Z\s]{2,50}$', name))

def validate_emergency_contact(contact):
    if not contact:
        return False
    return validate_phone(contact)

# Twilio configuration
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')

# Initialize Twilio client
twilio_client = None
if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
    twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# Initialize database
try:
    init_db()
except Exception as e:
    print(f"Warning: Database initialization failed: {str(e)}")
    print("The application will continue to run but database features may not work.")

# Function to generate OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Function to send OTP email
def send_otp_email(email, otp):
    try:
        msg = Message(
            'Your OTP for Women Safety App',
            recipients=[email],
            body=f'Your OTP for verification is: {otp}\nThis OTP will expire in 10 minutes.'
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

# Function to send verification email
def send_verification_email(email, otp):
    try:
        msg = Message(
            'Verify Your Email - Women Safety App',
            recipients=[email],
            body=f'''Welcome to Women Safety App!
            
Your verification code is: {otp}
            
Please enter this code to verify your email address. This code will expire in 10 minutes.

If you did not register for Women Safety App, please ignore this email.'''
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending verification email: {str(e)}")
        return False

# Login required decorator
def login_required(f):
    def decorated_function(*args, **kwargs):
        if not session.get('login_verified'):
            flash('Please login to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__  # Preserve the original function name
    return decorated_function

# Initialize Women Safety Analytics
analytics = WomenSafetyAnalytics()

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            data = request.form
            
            if not validate_name(data['firstName']):
                flash('Invalid first name. Please use only letters and spaces.')
                return redirect(url_for('register'))
            
            if not validate_name(data['lastName']):
                flash('Invalid last name. Please use only letters and spaces.')
                return redirect(url_for('register'))
            
            if not validate_email(data['email']):
                flash('Invalid email address.')
                return redirect(url_for('register'))
            
            if not validate_phone(data['phone']):
                flash('Invalid phone number. Please enter a valid 10-digit phone number.')
                return redirect(url_for('register'))
            
            if not validate_password(data['password']):
                flash('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number.')
                return redirect(url_for('register'))
            
            if users is None:
                flash('Database connection error. Please try again later.')
                return redirect(url_for('register'))
            
            if users.find_one({'email': data['email']}):
                flash('Email already registered')
                return redirect(url_for('register'))
            
            otp = generate_otp()
            
            user = {
                'firstName': data['firstName'].strip(),
                'lastName': data['lastName'].strip(),
                'email': data['email'].lower().strip(),
                'phone': re.sub(r'\D', '', data['phone']),
                'password': generate_password_hash(data['password']),
                'created_at': datetime.utcnow(),
                'is_verified': False,
                'verification_otp': otp,
                'verification_otp_timestamp': datetime.utcnow().timestamp()
            }
            
            if send_verification_email(user['email'], otp):
                users.insert_one(user)
                session['verification_email'] = user['email']
                flash('Please check your email for verification code.')
                return redirect(url_for('verify_email'))
            else:
                flash('Failed to send verification email. Please try again.')
                return redirect(url_for('register'))
                
        except Exception as e:
            print(f"Registration error: {str(e)}")
            flash('An error occurred during registration. Please try again.')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            data = request.form
            
            if not validate_email(data['email']):
                flash('Invalid email address.')
                return redirect(url_for('login'))
            
            if not data['password']:
                flash('Password is required.')
                return redirect(url_for('login'))
            
            if users is None:
                flash('Database connection error. Please try again later.')
                return redirect(url_for('login'))
            
            user = users.find_one({'email': data['email'].lower().strip()})
            if not user:
                flash('Invalid email or password')
                return redirect(url_for('login'))
                
            if not user.get('is_verified', False):
                session['verification_email'] = user['email']
                flash('Please verify your email address first.')
                return redirect(url_for('verify_email'))
                
            if check_password_hash(user['password'], data['password']):
                otp = generate_otp()
                session['login_otp'] = otp
                session['login_email'] = user['email']
                session['login_verified'] = False
                session['otp_timestamp'] = datetime.utcnow().timestamp()
                
                if send_otp_email(user['email'], otp):
                    flash('Please check your email for OTP verification.')
                    return redirect(url_for('verify_otp'))
                else:
                    flash('Failed to send OTP. Please try again.')
                    return redirect(url_for('login'))
            
            flash('Invalid email or password')
            return redirect(url_for('login'))
        except Exception as e:
            flash('An error occurred during login. Please try again.')
            print(f"Login error: {str(e)}")
            return redirect(url_for('login'))
    
    return render_template('login.html', google_auth_url=url_for('google_login'))

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    if 'verification_email' not in session:
        return redirect(url_for('register'))
        
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        email = session.get('verification_email')
        
        if users is None:
            flash('Database connection error. Please try again later.')
            return redirect(url_for('register'))
        
        user = users.find_one({'email': email})
        
        if not user:
            flash('User not found. Please register again.')
            return redirect(url_for('register'))
            
        stored_otp = user.get('verification_otp')
        otp_timestamp = user.get('verification_otp_timestamp')
        
        current_time = datetime.utcnow().timestamp()
        if current_time - otp_timestamp > 600:
            flash('Verification code has expired. Please register again.')
            users.delete_one({'email': email})
            return redirect(url_for('register'))
            
        if entered_otp == stored_otp:
            users.update_one(
                {'email': email},
                {
                    '$set': {'is_verified': True},
                    '$unset': {'verification_otp': "", 'verification_otp_timestamp': ""}
                }
            )
            session.pop('verification_email', None)
            flash('Email verified successfully! Please login.')
            return redirect(url_for('login'))
        else:
            flash('Invalid verification code. Please try again.')
            
    return render_template('verify_email.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'login_email' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        stored_otp = session.get('login_otp')
        otp_timestamp = session.get('otp_timestamp')
        
        current_time = datetime.utcnow().timestamp()
        if current_time - otp_timestamp > 600:
            flash('OTP has expired. Please login again.')
            return redirect(url_for('login'))
            
        if entered_otp == stored_otp:
            session['login_verified'] = True
            session.pop('login_otp', None)
            session.pop('otp_timestamp', None)
            flash('Login successful!')
            return redirect(url_for('home'))
        else:
            flash('Invalid OTP. Please try again.')
            
    return render_template('verify_otp.html')

@app.route('/resend-verification')
def resend_verification():
    if 'verification_email' not in session:
        return redirect(url_for('register'))
        
    email = session.get('verification_email')
    
    if users is None:
        flash('Database connection error. Please try again later.')
        return redirect(url_for('register'))
    
    user = users.find_one({'email': email})
    
    if not user:
        flash('User not found. Please register again.')
        return redirect(url_for('register'))
        
    otp = generate_otp()
    
    users.update_one(
        {'email': email},
        {
            '$set': {
                'verification_otp': otp,
                'verification_otp_timestamp': datetime.utcnow().timestamp()
            }
        }
    )
    
    if send_verification_email(email, otp):
        flash('New verification code has been sent to your email.')
    else:
        flash('Failed to send verification code. Please try again.')
        
    return redirect(url_for('verify_email'))

@app.route('/resend-otp')
def resend_otp():
    if 'login_email' not in session:
        return redirect(url_for('login'))
        
    otp = generate_otp()
    session['login_otp'] = otp
    session['otp_timestamp'] = datetime.utcnow().timestamp()
    
    if send_otp_email(session['login_email'], otp):
        flash('New OTP has been sent to your email.')
    else:
        flash('Failed to send OTP. Please try again.')
        
    return redirect(url_for('verify_otp'))

@app.route('/home')
@login_required
def home():
    return render_template('index.html')

@app.route('/emergency')
@login_required
def emergency():
    return render_template('emergency.html')

@app.route('/trigger_sos', methods=['POST'])
@login_required
def trigger_sos():
    try:
        data = request.get_json()
        primary_contact = data.get('primary')
        secondary_contact = data.get('secondary')
        
        if not primary_contact and not secondary_contact:
            return jsonify({'error': 'No emergency contacts found'}), 400
        
        if primary_contact and twilio_client:
            try:
                twilio_client.messages.create(
                    body='EMERGENCY: Your contact has triggered the SOS feature in Women Safety App. Please check on them immediately!',
                    from_=TWILIO_PHONE_NUMBER,
                    to=primary_contact
                )
            except Exception as e:
                print(f"Error sending SMS to primary contact: {str(e)}")
        
        if secondary_contact and twilio_client:
            try:
                twilio_client.messages.create(
                    body='EMERGENCY: Your contact has triggered the SOS feature in Women Safety App. Please check on them immediately!',
                    from_=TWILIO_PHONE_NUMBER,
                    to=secondary_contact
                )
            except Exception as e:
                print(f"Error sending SMS to secondary contact: {str(e)}")
        
        return jsonify({'message': 'SOS triggered successfully'})
    except Exception as e:
        print(f"SOS error: {str(e)}")
        return jsonify({'error': 'Failed to trigger SOS'}), 500

@app.route('/volunteer', methods=['GET', 'POST'])
def volunteer():
    if request.method == 'POST':
        try:
            data = request.form
            
            if not validate_name(data['firstName']):
                flash('Invalid first name. Please use only letters and spaces.')
                return redirect(url_for('volunteer'))
            
            if not validate_name(data['lastName']):
                flash('Invalid last name. Please use only letters and spaces.')
                return redirect(url_for('volunteer'))
            
            if not validate_email(data['email']):
                flash('Invalid email address.')
                return redirect(url_for('volunteer'))
            
            if not validate_phone(data['phone']):
                flash('Invalid phone number. Please enter a valid 10-digit phone number.')
                return redirect(url_for('volunteer'))
            
            if not data['experience'] or len(data['experience'].strip()) < 10:
                flash('Please provide a valid experience description.')
                return redirect(url_for('volunteer'))
            
            if not data['availability']:
                flash('Please specify your availability.')
                return redirect(url_for('volunteer'))
            
            if volunteers is None:
                flash('Database connection error. Please try again later.')
                return redirect(url_for('volunteer'))
            
            volunteer_data = {
                'firstName': data['firstName'].strip(),
                'lastName': data['lastName'].strip(),
                'email': data['email'].lower().strip(),
                'phone': re.sub(r'\D', '', data['phone']),
                'experience': data['experience'].strip(),
                'availability': data['availability'].strip(),
                'created_at': datetime.utcnow()
            }
            
            volunteers.insert_one(volunteer_data)
            flash('Thank you for volunteering! We will contact you soon.')
            return redirect(url_for('home'))
        except Exception as e:
            flash('An error occurred during volunteer registration. Please try again.')
            print(f"Volunteer registration error: {str(e)}")
            return redirect(url_for('volunteer'))
    
    return render_template('volunteer.html')

@app.route('/safety-tips')
@login_required
def safety_tips():
    try:
        if safety_tips is None:
            flash('Database connection error. Please try again later.')
            return render_template('safety.html', tips=[])
            
        tips = list(safety_tips.find({}, {'_id': 0}))
        return render_template('safety.html', tips=tips)
    except Exception as e:
        print(f"Error fetching safety tips: {str(e)}")
        return render_template('safety.html', tips=[])

@app.route('/api/safety-tips')
def get_safety_tips():
    try:
        if safety_tips is None:
            return jsonify([])
            
        tips = list(safety_tips.find({}, {'_id': 0}))
        return jsonify(tips)
    except Exception as e:
        print(f"Error fetching safety tips API: {str(e)}")
        return jsonify([])

@app.route('/api/emergency-contacts', methods=['GET', 'POST'])
def emergency_contacts():
    try:
        if emergency_contacts is None:
            return jsonify({'error': 'Database connection error'})
            
        if request.method == 'POST':
            data = request.json
            emergency_contacts.insert_one(data)
            return jsonify({'message': 'Emergency contact added successfully'})
        
        contacts = list(emergency_contacts.find({}, {'_id': 0}))
        return jsonify(contacts)
    except Exception as e:
        print(f"Error in emergency contacts API: {str(e)}")
        return jsonify({'error': 'Failed to process request'})

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    """Admin dashboard for managing backups"""
    try:
        backups = list_backups()
        return render_template('admin_dashboard.html', backups=backups)
    except Exception as e:
        print(f"Admin dashboard error: {str(e)}")
        flash('Error accessing admin dashboard')
        return redirect(url_for('home'))

@app.route('/admin/backup', methods=['POST'])
@login_required
def create_backup():
    """Create a new backup"""
    try:
        success, result = create_backup()
        if success:
            flash('Backup created successfully!')
        else:
            flash(f'Failed to create backup: {result}')
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        print(f"Backup creation error: {str(e)}")
        flash('Error creating backup')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/restore', methods=['POST'])
@login_required
def restore_backup():
    """Restore from a backup"""
    try:
        backup_file = request.form.get('backup_file')
        if not backup_file:
            flash('No backup file specified')
            return redirect(url_for('admin_dashboard'))
            
        success, message = restore_backup(backup_file)
        if success:
            flash('Backup restored successfully!')
        else:
            flash(f'Failed to restore backup: {message}')
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        print(f"Backup restore error: {str(e)}")
        flash('Error restoring backup')
        return redirect(url_for('admin_dashboard'))

@app.route('/google/login')
def google_login():
    """Initiate Google SSO login"""
    auth_url = get_google_auth_url()
    return redirect(auth_url)

@app.route('/google/callback')
def google_callback():
    """Handle Google SSO callback"""
    success, message = handle_google_callback()
    if success:
        flash('Login successful!')
        return redirect(url_for('home'))
    else:
        flash(f'Login failed: {message}')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """Handle user logout"""
    session.clear()
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))

@app.route('/analytics/dashboard')
@login_required
def analytics_dashboard():
    """Display the analytics dashboard"""
    return render_template('analytics_dashboard.html')

@app.route('/analytics/process-frame', methods=['POST'])
@login_required
def process_frame():
    """Process a single frame from the camera feed"""
    try:
        if 'frame' not in request.files:
            return jsonify({'error': 'No frame provided'}), 400
            
        frame_file = request.files['frame']
        if not frame_file.filename:
            return jsonify({'error': 'No file selected'}), 400
            
        # Read the frame data
        frame_bytes = frame_file.read()
        if not frame_bytes:
            return jsonify({'error': 'Empty frame data'}), 400
        
        # Convert bytes to numpy array
        nparr = np.frombuffer(frame_bytes, np.uint8)
        frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if frame is None:
            return jsonify({'error': 'Failed to decode frame'}), 400
            
        # Process frame using analytics
        results = analytics.process_frame(frame)
        
        return jsonify(results)
    except Exception as e:
        print(f"Frame processing error: {str(e)}")
        return jsonify({'error': 'Failed to process frame'}), 500

@app.route('/analytics/hotspots')
@login_required
def get_hotspots():
    """Get identified hotspots"""
    try:
        hotspots = analytics.get_hotspots()
        return jsonify({'hotspots': hotspots})
    except Exception as e:
        print(f"Hotspot retrieval error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve hotspots'}), 500

@app.route('/analytics/statistics')
@login_required
def get_statistics():
    """Get analytics statistics"""
    try:
        stats = {
            'total_alerts': sum(len(alerts) for alerts in analytics.historical_data.values()),
            'high_severity_alerts': sum(
                1 for alerts in analytics.historical_data.values()
                for alert in alerts
                if alert.get('severity') == 'high'
            ),
            'gender_distribution': {
                'total_men': sum(
                    data['men_count'] for alerts in analytics.historical_data.values()
                    for data in alerts
                ),
                'total_women': sum(
                    data['women_count'] for alerts in analytics.historical_data.values()
                    for data in alerts
                )
            }
        }
        return jsonify(stats)
    except Exception as e:
        print(f"Statistics retrieval error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve statistics'}), 500

if __name__ == '__main__':
    print("Starting the Women Safety application...")
    print("Access the website at: http://localhost:5000")
    app.run(debug=True) 