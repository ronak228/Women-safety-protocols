from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file, Response
from database import init_db, get_db, close_db, users, volunteers, emergency_contacts, safety_tips
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from twilio.rest import Client
from dotenv import load_dotenv
import re
import random
import string
from flask_mail import Mail, Message
from backup_restore import create_backup, restore_backup, list_backups
from sso import get_google_auth_url, handle_google_callback
import cv2
import base64
from io import BytesIO
from PIL import Image
import logging
from geopy.geocoders import Nominatim
from functools import wraps
import traceback
import json
from location_tracker import LocationTracker
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo import MongoClient
from bson import ObjectId

# Try to import analytics module, but don't fail if it's not available
try:
    from analytics.safety_analytics import WomenSafetyAnalytics
    has_analytics = True
except ImportError:
    print("Warning: Analytics module not available. Analytics features will be disabled.")
    has_analytics = False

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key')

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# MongoDB connection
MONGO_URI = os.getenv('MONGODB_URI')
client = MongoClient(MONGO_URI)
db = client[os.getenv('DB_NAME', 'women_safety')]

# Initialize location tracker
location_tracker = LocationTracker(db)

def get_db():
    """Get database connection"""
    return db

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.user_data = user_data
        
    def get_id(self):
        return str(self.user_data.get('_id'))

# Validate required environment variables
required_env_vars = ['EMAIL_USER', 'EMAIL_PASSWORD', 'MONGODB_URI']
missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    print(f"Warning: Missing required environment variables: {', '.join(missing_vars)}")
    print("Email functionality may not work correctly.")

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('EMAIL_USER')
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_ASCII_ATTACHMENTS'] = False
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEBUG'] = True
app.config['MAIL_SUPPRESS_SEND'] = False
app.config['MAIL_SEND_FAILED_SILENTLY'] = False
app.config['MAIL_USE_SSL'] = False

# Initialize Flask-Mail after all configurations
mail = Mail()
mail.init_app(app)

# Test email configuration
# def test_email_config():
#     try:
#         print("\nEmail Configuration:")
#         print(f"Server: {app.config['MAIL_SERVER']}")
#         print(f"Port: {app.config['MAIL_PORT']}")
#         print(f"Username: {app.config['MAIL_USERNAME']}")
#         print(f"TLS: {app.config['MAIL_USE_TLS']}")
#         print(f"SSL: {app.config['MAIL_USE_SSL']}")
#         print(f"Debug: {app.config['MAIL_DEBUG']}")
#         
#         # Test sending an email
#         with app.app_context():
#             msg = Message('Test Email',
#                          recipients=[app.config['MAIL_USERNAME']],
#                          body='This is a test email to verify the email configuration.')
#             mail.send(msg)
#             print("Test email sent successfully!")
#             return True
#     except Exception as e:
#         print(f"Error testing email configuration: {str(e)}")
#         print(f"Error type: {type(e).__name__}")
#         print(f"Full traceback: {traceback.format_exc()}")
#         return False

# Test email configuration on startup
# test_email_config()

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

# Initialize geolocator
geolocator = Nominatim(user_agent="WomenSafetyApp")

# Initialize database
try:
    init_db()
    print("Database collections initialized successfully!")
except Exception as e:
    print(f"Warning: Database initialization failed: {str(e)}")
    print("The application will continue to run but database features may not work.")

# Initialize analytics if available
analytics = None
if has_analytics:
    try:
        analytics = WomenSafetyAnalytics()
    except Exception as e:
        print(f"Warning: Failed to initialize analytics: {str(e)}")
        print("The application will continue to run but analytics features will be disabled.")

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
        
        with app.app_context():
            mail.send(msg)
            logger.info(f"OTP email sent successfully to {email}")
            return True
    except Exception as e:
        logger.error(f"Error sending OTP email: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
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
        
        with app.app_context():
            mail.send(msg)
            logger.info(f"Verification email sent successfully to {email}")
            return True
    except Exception as e:
        logger.error(f"Error sending verification email: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return False

# Add this after app initialization
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('login_verified'):
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    """Root route - redirect to appropriate page"""
    if not session.get('login_verified'):
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

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
    if request.method == 'GET':
        return render_template('login.html', google_auth_url=url_for('google_login'))
    
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').lower().strip()
            password = request.form.get('password', '')
            
            if not email or not password:
                flash('Please provide both email and password.')
                return redirect(url_for('login'))
            
            # Get database connection
            db = get_db()
            
            # Find user by email
            user = db.users.find_one({'email': email})
            
            if not user:
                flash('Invalid email or password.')
                return redirect(url_for('login'))
            
            if not user.get('is_verified', False):
                flash('Please verify your email before logging in.')
                return redirect(url_for('login'))
            
            if check_password_hash(user['password'], password):
                # Generate and send OTP
                otp = generate_otp()
                if send_otp_email(email, otp):
                    # Store OTP and email in session
                    session['login_otp'] = otp
                    session['otp_timestamp'] = datetime.utcnow().timestamp()
                    session['login_email'] = email
                    session['temp_user_id'] = str(user['_id'])  # Store user ID temporarily
                    return redirect(url_for('verify_otp'))
                else:
                    flash('Failed to send OTP. Please try again.')
                    return redirect(url_for('login'))
            
            flash('Invalid email or password.')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login. Please try again.')
            return redirect(url_for('login'))

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
    if 'login_email' not in session or 'temp_user_id' not in session:
        flash('Session expired. Please login again.')
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        try:
            entered_otp = request.form.get('otp')
            stored_otp = session.get('login_otp')
            otp_timestamp = session.get('otp_timestamp')
            login_email = session.get('login_email')
            temp_user_id = session.get('temp_user_id')
            
            current_time = datetime.utcnow().timestamp()
            if current_time - otp_timestamp > 600:  # 10 minutes expiry
                flash('OTP has expired. Please login again.')
                session.clear()
                return redirect(url_for('login'))
                
            if entered_otp == stored_otp:
                # Get user data
                db = get_db()
                user = db.users.find_one({'_id': ObjectId(temp_user_id)})
                
                if not user:
                    flash('User not found. Please login again.')
                    session.clear()
                    return redirect(url_for('login'))
                
                # Set session data
                session['login_verified'] = True
                session['user_id'] = temp_user_id
                session['user_email'] = user['email']
                session['name'] = f"{user.get('firstName', '')} {user.get('lastName', '')}".strip() or 'User'
                
                # Clean up temporary session data
                session.pop('login_otp', None)
                session.pop('otp_timestamp', None)
                session.pop('login_email', None)
                session.pop('temp_user_id', None)
                
                flash('Login successful!')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid OTP. Please try again.')
                
        except Exception as e:
            logger.error(f"OTP verification error: {str(e)}")
            flash('An error occurred during OTP verification. Please try again.')
            return redirect(url_for('login'))
            
    return render_template('verify_otp.html')

@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Please provide your email address.')
            return redirect(url_for('resend_verification'))
            
        if users is None:
            flash('Database connection error. Please try again later.')
            return redirect(url_for('resend_verification'))
        
        user = users.find_one({'email': email.lower().strip()})
        
        if not user:
            flash('Email not found. Please register first.')
            return redirect(url_for('register'))
            
        if user.get('is_verified', False):
            flash('Email is already verified. Please login.')
            return redirect(url_for('login'))
            
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
            session['verification_email'] = email
            flash('New verification code has been sent to your email.')
            return redirect(url_for('verify_email'))
        else:
            flash('Failed to send verification code. Please try again.')
            return redirect(url_for('resend_verification'))
    
    return render_template('resend_verification.html')

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
    try:
        if not session.get('login_verified'):
            flash('Please login to access this page.')
            return redirect(url_for('login'))
            
        # Get user data
        user_id = session.get('user_id')
        if not user_id:
            flash('Session expired. Please login again.')
            return redirect(url_for('login'))
            
        user = users.find_one({'_id': ObjectId(user_id)})
        if not user:
            flash('User not found. Please login again.')
            return redirect(url_for('login'))
            
        # Get only the 5 most recent alerts for the current user
        recent_alerts = list(db.alerts.find(
            {'user_id': ObjectId(user_id)}
        ).sort(
            [('timestamp', -1)]  # Sort by timestamp in descending order (newest first)
        ).limit(5))  # Strictly limit to 5 alerts
            
        return render_template('index.html', user=user, recent_alerts=recent_alerts)
    except Exception as e:
        logger.error(f"Home page error: {str(e)}")
        flash('An error occurred. Please try again.')
        return redirect(url_for('login'))

@app.route('/emergency')
@login_required
def emergency():
    """Emergency page"""
    emergency_numbers = {
        'Police': '100',
        'Women Helpline': '1091',
        'Ambulance': '102',
        'National Emergency': '112'
    }
    return render_template('emergency.html', emergency_numbers=emergency_numbers)

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
    """Safety tips page"""
    tips = [
        {
            'title': 'Stay Aware of Surroundings',
            'description': 'Always be aware of your surroundings and trust your instincts.'
        },
        {
            'title': 'Share Location',
            'description': 'Share your location with trusted contacts when traveling.'
        },
        {
            'title': 'Emergency Contacts',
            'description': 'Keep emergency contacts easily accessible.'
        },
        {
            'title': 'Safe Routes',
            'description': 'Plan your route in advance and stick to well-lit, populated areas.'
        },
        {
            'title': 'Self-Defense',
            'description': 'Consider learning basic self-defense techniques.'
        }
    ]
    return render_template('safety_tips.html', tips=tips)

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
@login_required
def emergency_contacts():
    try:
        # Get user ID from session
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        if request.method == 'POST':
            # Verify content type
            if not request.is_json:
                return jsonify({
                    'success': False,
                    'message': 'Content-Type must be application/json'
                }), 400

            # Get JSON data
            data = request.get_json()
            if not data:
                return jsonify({
                    'success': False,
                    'message': 'No data provided'
                }), 400

            # Validate required fields
            required_fields = ['name', 'email', 'relationship', 'phone']
            for field in required_fields:
                if not data.get(field):
                    return jsonify({
                        'success': False,
                        'message': f'Missing required field: {field}'
                    }), 400

            # Create contact document
            contact = {
                'user_id': user_id,
                'name': data['name'].strip(),
                'email': data['email'].lower().strip(),
                'relationship': data['relationship'].strip(),
                'phone': data['phone'].strip(),
                'created_at': datetime.utcnow()
            }

            # Insert into database
            result = db.emergency_contacts.insert_one(contact)
            
            # Return success response with contact data
            contact['_id'] = str(result.inserted_id)
            return jsonify({
                'success': True,
                'message': 'Contact added successfully',
                'contact': contact
            })

        # GET method - return list of contacts
        contacts = list(db.emergency_contacts.find({'user_id': user_id}))
        for contact in contacts:
            contact['_id'] = str(contact['_id'])
        return jsonify(contacts)

    except Exception as e:
        logger.error(f"Error in emergency contacts API: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while processing your request'
        }), 500

@app.route('/api/emergency-contacts/<contact_id>', methods=['DELETE'])
@login_required
def delete_contact_api(contact_id):
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'success': False, 'message': 'User not authenticated'}), 401

        db = get_db()
        
        # Convert contact_id to ObjectId
        try:
            contact_id_obj = ObjectId(contact_id)
        except:
            return jsonify({'success': False, 'message': 'Invalid contact ID'}), 400

        # Delete contact and ensure it belongs to the current user
        result = db.emergency_contacts.delete_one({
            '_id': contact_id_obj,
            'user_id': user_id
        })

        if result.deleted_count > 0:
            return jsonify({
                'success': True,
                'message': 'Contact deleted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Contact not found or unauthorized to delete'
            }), 404

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Failed to delete contact: {str(e)}'
        }), 500

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
def admin_create_backup():
    """Create a new backup"""
    try:
        success, result = create_backup()
        if success:
            flash('Backup created successfully!')
        else:
            flash(f'Failed to create backup: {result}')
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        flash(f'Error creating backup: {str(e)}')
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
    """Initiate Google login"""
    try:
        # Clear any existing OAuth state
        session.clear()
        session.modified = True
        
        # Get Google auth URL
        auth_url = get_google_auth_url()
        if not auth_url:
            logger.error("Failed to generate Google auth URL")
            flash("Error initiating Google login. Please try again.", "error")
            return redirect(url_for('login'))
            
        logger.info("Redirecting to Google login page")
        return redirect(auth_url)
    except Exception as e:
        logger.error(f"Error in Google login: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        flash("Error initiating Google login. Please try again.", "error")
        return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    try:
        # Get user's email and ID from session
        user_id = session.get('user_id')
        email = session.get('user_email')
        
        if not email or not user_id:
            flash('Please log in to access the dashboard.')
            return redirect(url_for('login'))
        
        # Get database connection
        db = get_db()
        
        # Get user data using ObjectId
        user = db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            flash('User not found. Please login again.')
            session.clear()
            return redirect(url_for('login'))
            
        # Get user's emergency contacts
        emergency_contacts = list(db.emergency_contacts.find({'user_id': user_id}))
        
        # Get location history
        location_history = location_tracker.get_user_location_history(user_id)
        
        # Get analytics data
        analytics_data = {
            'total_incidents': 0,
            'high_severity_alerts': 0,
            'dates': [],
            'scores': []
        }
        
        # Get last 7 days of analytics
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        
        # Get safety scores from the database
        daily_scores = db.safety_scores.find({
            'user_id': user_id,
            'date': {'$gte': start_date, '$lte': end_date}
        }).sort('date', 1)
        
        # Process safety scores
        for score in daily_scores:
            analytics_data['dates'].append(score['date'].strftime('%Y-%m-%d'))
            analytics_data['scores'].append(score.get('score', 0))
            analytics_data['total_incidents'] += score.get('incidents', 0)
            analytics_data['high_severity_alerts'] += score.get('high_severity', 0)
        
        # If no scores exist, provide default data for the chart
        if not analytics_data['dates']:
            for i in range(7):
                date = (end_date - timedelta(days=i)).strftime('%Y-%m-%d')
                analytics_data['dates'].insert(0, date)
                analytics_data['scores'].insert(0, 0)
        
        # Get 5 most recent alerts for the current user
        alert_history = list(db.alerts.find(
            {'user_id': user_id}  # Use user_id directly since it's already a string
        ).sort(
            [('timestamp', -1)]  # Sort by timestamp in descending order (newest first)
        ).limit(5))  # Get only 5 most recent alerts
        
        # Render dashboard template with all data
        return render_template('user_dashboard.html',
                             user=user,
                             emergency_contacts=emergency_contacts,
                             location_history=location_history,
                             analytics=analytics_data,
                             alert_history=alert_history)
                             
    except Exception as e:
        logger.error(f"Error in dashboard: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        flash('An error occurred while loading the dashboard.')
        return redirect(url_for('login'))

@app.route('/google/callback')
def google_callback():
    """Handle Google OAuth callback"""
    try:
        logger.info("Received Google callback")
        
        # Handle Google callback
        user_info = handle_google_callback()
        if not user_info:
            logger.error("Failed to handle Google callback")
            flash("Error during Google login. Please try again.", "error")
            return redirect(url_for('login'))
            
        # Extract user information
        email = user_info['email']
        name = user_info['name'].split()
        first_name = name[0] if name else ''
        last_name = name[1] if len(name) > 1 else ''
        
        # Check if user exists
        user = users.find_one({'email': email})
        
        if not user:
            # Create new user
            user = {
                'firstName': first_name,
                'lastName': last_name,
                'email': email,
                'created_at': datetime.utcnow(),
                'is_verified': True,  # Google-verified users are pre-verified
                'google_id': user_info.get('sub', '')
            }
            users.insert_one(user)
            logger.info(f"Created new user: {email}")
        
        # Set session variables
        session['login_verified'] = True
        session['user_email'] = email
        session['user_id'] = str(user['_id'])
        session['name'] = f"{first_name} {last_name}".strip() or 'User'
        session.modified = True
        
        logger.info(f"Successfully logged in user: {email}")
        flash("Successfully logged in with Google!", "success")
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Error in Google callback: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        flash("Error during Google login. Please try again.", "error")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """Handle user logout"""
    session.clear()
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))

@app.route('/analytics')
@login_required
def analytics_dashboard():
    if not has_analytics:
        flash('Analytics features are currently unavailable.', 'warning')
        return redirect(url_for('home'))
    return render_template('analytics.html')

@app.route('/api/analytics/stats')
@login_required
def get_analytics_stats():
    if not has_analytics:
        return jsonify({'error': 'Analytics features are currently unavailable'}), 503
    try:
        stats = WomenSafetyAnalytics.get_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/hotspots')
@login_required
def get_hotspots():
    if not has_analytics:
        return jsonify({'error': 'Analytics features are currently unavailable'}), 503
    try:
        hotspots = WomenSafetyAnalytics.get_hotspots()
        return jsonify(hotspots)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/update_hotspot')
@login_required
def update_hotspot():
    if not has_analytics:
        return jsonify({'error': 'Analytics features are currently unavailable'}), 503
    try:
        data = request.get_json()
        result = WomenSafetyAnalytics.update_hotspot(data)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/get_location', methods=['POST'])
def get_location():
    """Get user's current location"""
    try:
        # Get location from request
        data = request.get_json()
        if not data or 'latitude' not in data or 'longitude' not in data:
            return jsonify({
                'success': False,
                'message': 'Location data not provided. Please enable location access in your browser settings.'
            }), 400

        latitude = float(data['latitude'])
        longitude = float(data['longitude'])
        
        # Get address from coordinates
        try:
            location = geolocator.reverse(f"{latitude}, {longitude}")
            address = location.address if location else "Location not found"
        except Exception as e:
            logger.error(f"Error getting address: {str(e)}")
            address = "Address not available"
        
        # Store location in session
        session['user_location'] = {
            'latitude': latitude,
            'longitude': longitude,
            'address': address
        }
        
        return jsonify({
            'success': True,
            'message': 'Location updated successfully',
            'address': address
        })
    except Exception as e:
        logger.error(f"Error in get_location: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error processing location data. Please try again.'
        }), 500

@app.route('/update_location', methods=['POST'])
@login_required
def update_location():
    """Update user's location"""
    try:
        data = request.get_json()
        if not data or 'latitude' not in data or 'longitude' not in data:
            return jsonify({
                'success': False,
                'message': 'Location data not provided'
            }), 400

        user_id = session.get('user_id')
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        try:
            latitude = float(data['latitude'])
            longitude = float(data['longitude'])
        except (ValueError, TypeError):
            return jsonify({
                'success': False,
                'message': 'Invalid location coordinates'
            }), 400

        # Validate coordinates
        if not (-90 <= latitude <= 90) or not (-180 <= longitude <= 180):
            return jsonify({
                'success': False,
                'message': 'Invalid location coordinates'
            }), 400
        
        # Try to update location in both collections
        try:
            # Get user info
            user = db.users.find_one({'_id': ObjectId(user_id)})
            if not user:
                return jsonify({
                    'success': False,
                    'message': 'User not found'
                }), 404

            # Update current location
            location_tracker.update_user_location(user_id, latitude, longitude)
            
            # Try to save location with geocoding
            try:
                location = location_tracker.save_location(user_id, latitude, longitude)
                
                # Get emergency contacts
                emergency_contacts = list(db.emergency_contacts.find({'user_id': user_id}))
                
                # Create Google Maps link
                google_maps_link = f"https://www.google.com/maps?q={latitude},{longitude}"
                
                # Send email to emergency contacts
                for contact in emergency_contacts:
                    subject = f"Location Update from {user.get('firstName', '')} {user.get('lastName', '')}"
                    message = f"""
                    Location Update

                    {user.get('firstName', '')} {user.get('lastName', '')} has shared their location with you.

                    View their location here: {google_maps_link}

                    This is an automated message from the Women Safety App.
                    """
                    
                    send_alert_email(contact['email'], subject, message)
                
            except Exception as e:
                logger.warning(f"Geocoding or email sending failed but location was saved: {str(e)}")
            
            return jsonify({
                'success': True,
                'message': 'Location updated and shared successfully'
            })
            
        except Exception as e:
            logger.error(f"Database error while updating location: {str(e)}")
            return jsonify({
                'success': False,
                'message': 'Failed to save location to database'
            }), 500

    except Exception as e:
        logger.error(f"Error updating location: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while updating location'
        }), 500

@app.route('/get_recent_locations')
@login_required
def get_recent_locations():
    """Get user's locations from the past 3 hours"""
    try:
        user_id = session.get('user_id')
        locations = location_tracker.get_recent_locations(user_id)
        
        return jsonify({
            'success': True,
            'locations': locations
        })
    except Exception as e:
        logger.error(f"Error getting recent locations: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to get recent locations'
        })

@app.route('/export_locations')
def export_locations():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    export_format = request.args.get('format', 'json')
    if export_format not in ['json', 'csv']:
        export_format = 'json'
        
    data = location_tracker.export_location_history(
        user_id=session['user_id'],
        format=export_format
    )
    
    if data is None:
        return jsonify({'error': 'Failed to export location history'})
        
    if export_format == 'json':
        return app.response_class(
            response=data,
            status=200,
            mimetype='application/json'
        )
    else:
        return app.response_class(
            response=data,
            status=200,
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=location_history.csv'}
        )

@app.route('/add_contact', methods=['POST'])
def add_contact():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
        
    name = request.form.get('name')
    phone = request.form.get('phone')
    relationship = request.form.get('relationship')
    
    if not all([name, phone, relationship]):
        return jsonify({'success': False, 'message': 'Missing required fields'})
        
    db = get_db()
    result = db.emergency_contacts.insert_one({
        'user_id': session['user_id'],
        'name': name,
        'phone': phone,
        'relationship': relationship,
        'created_at': datetime.now()
    })
    
    return jsonify({'success': bool(result.inserted_id)})

@app.route('/delete_contact/<contact_id>', methods=['DELETE'])
def delete_contact(contact_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
        
    db = get_db()
    result = db.emergency_contacts.delete_one({
        '_id': contact_id,
        'user_id': session['user_id']
    })
    
    return jsonify({'success': bool(result.deleted_count)})

@app.route('/trigger_emergency', methods=['POST'])
@login_required
def trigger_emergency():
    """Trigger emergency alert"""
    try:
        user_id = session.get('user_id')
        user = db.users.find_one({'_id': ObjectId(user_id)})
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
            
        # Get user's current location
        current_location = location_tracker.get_current_location(user_id)
        
        # Create emergency alert
        alert_data = {
            'user_id': user_id,
            'type': 'Emergency Alert',
            'message': 'Emergency alert triggered',
            'location': current_location,
            'timestamp': datetime.now(),
            'status': 'active'
        }
        db.alerts.insert_one(alert_data)
        
        # Get emergency contacts
        emergency_contacts = list(db.emergency_contacts.find({'user_id': user_id}))
        
        # Send email notifications to emergency contacts
        success_count = 0
        for contact in emergency_contacts:
            # Prepare email message
            subject = f"EMERGENCY ALERT from {user.get('firstName', '')} {user.get('lastName', '')}"
            message = f"""
            EMERGENCY ALERT!
            
            {user.get('firstName', '')} {user.get('lastName', '')} has triggered an emergency alert.
            
            Please check on them immediately!
            
            """
            
            # Add location information if available
            if current_location:
                google_maps_link = f"https://www.google.com/maps?q={current_location['latitude']},{current_location['longitude']}"
                message += f"\nLast known location: {google_maps_link}"
            
            # Send email notification
            if send_alert_email(contact['email'], subject, message):
                success_count += 1
                
        # Log the alert
        db.alerts.insert_one({
            'user_id': user_id,
            'subject': subject,
            'message': message,
            'sent_to': success_count,
            'total_contacts': len(emergency_contacts),
            'timestamp': datetime.utcnow()
        })
        
        return jsonify({
            'success': True,
            'message': f'Emergency alert sent to {success_count} out of {len(emergency_contacts)} contacts'
        })
        
    except Exception as e:
        logger.error(f"Error triggering emergency: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to trigger emergency alert'
        })

@app.route('/contact_emergency', methods=['POST'])
@login_required
def contact_emergency():
    """Contact emergency numbers"""
    try:
        user_id = session.get('user_id')
        user = db.users.find_one({'_id': ObjectId(user_id)})
        
        if not user:
            return jsonify({
                'success': False,
                'message': 'User not found'
            })
            
        # Get emergency contacts
        emergency_contacts = list(db.emergency_contacts.find({'user_id': user_id}))
        
        if not emergency_contacts:
            return jsonify({
                'success': False,
                'message': 'No emergency contacts found'
            })
            
        # Get current location
        current_location = location_tracker.get_current_location(user_id)
        
        # Send email notifications to emergency contacts
        success_count = 0
        for contact in emergency_contacts:
            # Prepare email message
            subject = f"EMERGENCY ALERT from {user.get('firstName', '')} {user.get('lastName', '')}"
            message = f"""
            EMERGENCY ALERT!
            
            {user.get('firstName', '')} {user.get('lastName', '')} has triggered an emergency alert.
            
            Please check on them immediately!
            
            """
            
            # Add location information if available
            if current_location:
                google_maps_link = f"https://www.google.com/maps?q={current_location['latitude']},{current_location['longitude']}"
                message += f"\nLast known location: {google_maps_link}"
            
            # Send email notification
            if send_alert_email(contact['email'], subject, message):
                success_count += 1
                
        # Log the alert
        db.alerts.insert_one({
            'user_id': user_id,
            'subject': subject,
            'message': message,
            'sent_to': success_count,
            'total_contacts': len(emergency_contacts),
            'timestamp': datetime.utcnow()
        })
            
        return jsonify({
            'success': True,
            'message': f'Emergency alert sent to {success_count} out of {len(emergency_contacts)} contacts'
        })
        
    except Exception as e:
        logger.error(f"Error contacting emergency: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to contact emergency numbers'
        })

def send_alert_email(email, subject, message):
    """Send alert message via email"""
    try:
        msg = Message(
            subject=subject,
            recipients=[email],
            body=message
        )
        
        with app.app_context():
            mail.send(msg)
            logger.info(f"Alert email sent successfully to {email}")
            return True
    except Exception as e:
        logger.error(f"Error sending alert email: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return False

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            flash('Please login to access your profile.')
            return redirect(url_for('login'))
            
        # Get user data using ObjectId
        user = db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            flash('User not found. Please login again.')
            session.clear()
            return redirect(url_for('login'))
            
        # Get emergency contacts
        emergency_contacts = list(db.emergency_contacts.find({'user_id': user_id}))
        
        # Get user's alerts
        alerts = list(db.alerts.find({
            'user_id': user_id
        }).sort('timestamp', -1).limit(5))
        
        # Format user data for template
        user_data = {
            'name': f"{user.get('firstName', '')} {user.get('lastName', '')}".strip() or 'User',
            'email': user.get('email', ''),
            'phone': user.get('phone', ''),
            'alerts': alerts,
            'settings': user.get('settings', {
                'locationTracking': True,
                'emailNotifications': True,
                'smsNotifications': True
            })
        }
        
        return render_template('profile.html',
                             user=user_data,
                             emergency_contacts=emergency_contacts)
                             
    except Exception as e:
        logger.error(f"Error loading profile: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        flash('An error occurred while loading your profile.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """Contact page and form handling"""
    if request.method == 'POST':
        try:
            # Get form data
            name = request.form.get('name')
            email = request.form.get('email')
            subject = request.form.get('subject')
            message = request.form.get('message')
            
            if not all([name, email, subject, message]):
                return jsonify({
                    'success': False,
                    'message': 'Please fill in all required fields'
                })
                
            # Save contact message to database
            contact_data = {
                'name': name,
                'email': email,
                'subject': subject,
                'message': message,
                'timestamp': datetime.now(),
                'status': 'new'
            }
            db.contact_messages.insert_one(contact_data)
            
            # Send email notification to admin
            admin_message = f"""
            New Contact Form Submission
            
            Name: {name}
            Email: {email}
            Subject: {subject}
            Message: {message}
            """
            
            send_email(
                to_email=app.config['ADMIN_EMAIL'],
                subject=f"New Contact Form: {subject}",
                body=admin_message
            )
            
            # Send confirmation email to user
            user_message = f"""
            Dear {name},
            
            Thank you for contacting us. We have received your message and will get back to you soon.
            
            Your message details:
            Subject: {subject}
            Message: {message}
            
            Best regards,
            Women Safety Portal Team
            """
            
            send_email(
                to_email=email,
                subject="Thank you for contacting Women Safety Portal",
                body=user_message
            )
            
            return jsonify({
                'success': True,
                'message': 'Message sent successfully'
            })
            
        except Exception as e:
            logger.error(f"Error processing contact form: {str(e)}")
            return jsonify({
                'success': False,
                'message': 'Failed to send message'
            })
            
    return render_template('contact.html')

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    """Update user profile"""
    try:
        user_id = session.get('user_id')
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').lower().strip()
        phone = request.form.get('phone', '').strip()
        
        if not all([name, email, phone]):
            return jsonify({
                'success': False,
                'message': 'Please fill in all required fields'
            })
            
        # Split name into first and last name
        name_parts = name.split(' ', 1)
        first_name = name_parts[0]
        last_name = name_parts[1] if len(name_parts) > 1 else ''
            
        # Get current user
        current_user = db.users.find_one({'_id': ObjectId(user_id)})
        if not current_user:
            return jsonify({
                'success': False,
                'message': 'User not found'
            })
            
        # Only check for email existence if email is being changed
        if email != current_user.get('email'):
            # Check if email is already taken by another user
            existing_user = db.users.find_one({
                '_id': {'$ne': ObjectId(user_id)},
                'email': email
            })
            if existing_user:
                return jsonify({
                    'success': False,
                    'message': 'Email is already taken'
                })
        
        # Validate phone number
        if not validate_phone(phone):
            return jsonify({
                'success': False,
                'message': 'Please enter a valid 10-digit phone number'
            })
            
        # Update user profile
        result = db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'firstName': first_name,
                'lastName': last_name,
                'email': email,
                'phone': phone,
                'updated_at': datetime.now()
            }}
        )
        
        if result.modified_count > 0:
            # Update session data
            session['user_email'] = email
            session['name'] = name
            
            return jsonify({
                'success': True,
                'message': 'Profile updated successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'No changes were made'
            })
            
    except Exception as e:
        logger.error(f"Error updating profile: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'message': 'Failed to update profile'
        })

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    try:
        user_id = session.get('user_id')
        current_password = request.form.get('currentPassword')
        new_password = request.form.get('newPassword')
        confirm_password = request.form.get('confirmPassword')
        
        if not all([current_password, new_password, confirm_password]):
            return jsonify({
                'success': False,
                'message': 'Please fill in all required fields'
            })
            
        if new_password != confirm_password:
            return jsonify({
                'success': False,
                'message': 'New passwords do not match'
            })
            
        # Get user from database
        user = db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({
                'success': False,
                'message': 'User not found'
            })
            
        # Verify current password
        if not check_password_hash(user['password'], current_password):
            return jsonify({
                'success': False,
                'message': 'Current password is incorrect'
            })
            
        # Update password
        hashed_password = generate_password_hash(new_password)
        result = db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'password': hashed_password,
                'updated_at': datetime.now()
            }}
        )
        
        if result.modified_count > 0:
            return jsonify({
                'success': True,
                'message': 'Password updated successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to update password'
            })
            
    except Exception as e:
        logger.error(f"Error changing password: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to change password'
        })

@app.route('/update_settings', methods=['POST'])
@login_required
def update_settings():
    """Update user settings"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        setting = data.get('setting')
        enabled = data.get('enabled')
        
        if setting not in ['locationTracking', 'emailNotifications', 'smsNotifications']:
            return jsonify({
                'success': False,
                'message': 'Invalid setting'
            })
            
        # Update user settings
        result = db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                f'settings.{setting}': enabled,
                'updated_at': datetime.now()
            }}
        )
        
        if result.modified_count > 0:
            return jsonify({
                'success': True,
                'message': 'Settings updated successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'No changes were made'
            })
            
    except Exception as e:
        logger.error(f"Error updating settings: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to update settings'
        })

@app.route('/add_emergency_contact', methods=['POST'])
@login_required
def add_emergency_contact():
    """Add emergency contact"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            })
            
        name = request.form.get('name')
        relationship = request.form.get('relationship')
        phone = request.form.get('phone')
        email = request.form.get('email')
        
        if not all([name, relationship, phone, email]):
            return jsonify({
                'success': False,
                'message': 'Please fill in all required fields'
            })
            
        # Validate phone number
        if not validate_phone(phone):
            return jsonify({
                'success': False,
                'message': 'Invalid phone number format'
            })
            
        # Validate email
        if not validate_email(email):
            return jsonify({
                'success': False,
                'message': 'Invalid email format'
            })
            
        # Add emergency contact
        contact_data = {
            'user_id': user_id,
            'name': name,
            'relationship': relationship,
            'phone': phone,
            'email': email,
            'created_at': datetime.now()
        }
        
        result = db.emergency_contacts.insert_one(contact_data)
        
        if result.inserted_id:
            return jsonify({
                'success': True,
                'message': 'Emergency contact added successfully',
                'contact': contact_data
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to add emergency contact'
            })
            
    except Exception as e:
        logger.error(f"Error adding emergency contact: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'message': 'Failed to add emergency contact'
        })

@app.route('/delete_emergency_contact/<contact_id>', methods=['DELETE'])
@login_required
def delete_emergency_contact(contact_id):
    """Delete emergency contact"""
    try:
        user_id = session.get('user_id')
        
        # Delete emergency contact
        result = db.emergency_contacts.delete_one({
            '_id': ObjectId(contact_id),
            'user_id': user_id
        })
        
        if result.deleted_count > 0:
            return jsonify({
                'success': True,
                'message': 'Emergency contact deleted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Contact not found or unauthorized'
            })
            
    except Exception as e:
        logger.error(f"Error deleting emergency contact: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to delete emergency contact'
        })

# Function to send password reset email
def send_password_reset_email(email, reset_token):
    try:
        reset_url = f"{request.host_url}reset-password/{reset_token}"
        msg = Message(
            'Password Reset - Women Safety App',
            recipients=[email],
            body=f'''Hello,

You have requested to reset your password for the Women Safety App.

Click the following link to reset your password:
{reset_url}

This link will expire in 30 minutes.

If you did not request this password reset, please ignore this email.

Best regards,
Women Safety Portal Team'''
        )
        
        with app.app_context():
            mail.send(msg)
            logger.info(f"Password reset email sent successfully to {email}")
            return True
    except Exception as e:
        logger.error(f"Error sending password reset email: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return False

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').lower().strip()
            
            if not email:
                flash('Please provide your email address.')
                return redirect(url_for('forgot_password'))
            
            # Get database connection
            db = get_db()
            
            # Find user by email
            user = db.users.find_one({'email': email})
            
            if not user:
                # Don't reveal if email exists or not for security
                flash('If an account exists with this email, you will receive password reset instructions.')
                return redirect(url_for('login'))
            
            # Generate reset token
            reset_token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            reset_expiry = datetime.utcnow() + timedelta(minutes=30)
            
            # Store reset token in database
            db.users.update_one(
                {'email': email},
                {
                    '$set': {
                        'reset_token': reset_token,
                        'reset_expiry': reset_expiry
                    }
                }
            )
            
            # Send reset email
            if send_password_reset_email(email, reset_token):
                flash('Password reset instructions have been sent to your email.')
            else:
                flash('Failed to send password reset email. Please try again.')
            
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Forgot password error: {str(e)}")
            flash('An error occurred. Please try again.')
            return redirect(url_for('forgot_password'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        try:
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not new_password or not confirm_password:
                flash('Please provide both new password and confirmation.')
                return redirect(url_for('reset_password', token=token))
            
            if new_password != confirm_password:
                flash('Passwords do not match.')
                return redirect(url_for('reset_password', token=token))
            
            if not validate_password(new_password):
                flash('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number.')
                return redirect(url_for('reset_password', token=token))
            
            # Get database connection
            db = get_db()
            
            # Find user with valid reset token
            user = db.users.find_one({
                'reset_token': token,
                'reset_expiry': {'$gt': datetime.utcnow()}
            })
            
            if not user:
                flash('Invalid or expired reset token. Please request a new password reset.')
                return redirect(url_for('forgot_password'))
            
            # Update password and clear reset token
            db.users.update_one(
                {'_id': user['_id']},
                {
                    '$set': {
                        'password': generate_password_hash(new_password),
                        'updated_at': datetime.utcnow()
                    },
                    '$unset': {
                        'reset_token': "",
                        'reset_expiry': ""
                    }
                }
            )
            
            flash('Password has been reset successfully. Please login with your new password.')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Reset password error: {str(e)}")
            flash('An error occurred. Please try again.')
            return redirect(url_for('reset_password', token=token))
    
    return render_template('reset_password.html', token=token)

if __name__ == '__main__':
    # Run the app on localhost
    app.run(host='localhost', port=5000, debug=True) 