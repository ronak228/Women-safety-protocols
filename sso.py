import os
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport import requests
from flask import session, url_for, current_app, request, redirect
from database import users
from datetime import datetime
import logging
import json
from functools import wraps
import traceback
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Allow insecure transport for development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Google OAuth 2.0 configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = "http://localhost:5000/google/callback"

# OAuth 2.0 scopes
SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]

def get_google_auth_url():
    """Generate Google OAuth URL"""
    try:
        # Create OAuth flow
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [GOOGLE_REDIRECT_URI],
                    "scopes": SCOPES
                }
            },
            scopes=SCOPES,
            redirect_uri=GOOGLE_REDIRECT_URI
        )
        
        # Generate authorization URL
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        # Store state and flow configuration in session
        session['oauth_state'] = state
        session['oauth_config'] = {
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'auth_uri': "https://accounts.google.com/o/oauth2/auth",
            'token_uri': "https://oauth2.googleapis.com/token",
            'redirect_uris': [GOOGLE_REDIRECT_URI],
            'scopes': SCOPES
        }
        session.modified = True
        
        logger.info(f"Generated auth URL with state: {state}")
        return auth_url
    except Exception as e:
        logger.error(f"Error generating auth URL: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return None

def handle_google_callback():
    """Handle Google OAuth callback"""
    try:
        # Get state and config from session
        state = session.get('oauth_state')
        config = session.get('oauth_config')
        
        if not state or not config:
            logger.error("Missing OAuth state or config in session")
            return None
            
        # Recreate flow from config
        flow = Flow.from_client_config(
            {"web": config},
            scopes=config['scopes'],
            redirect_uri=config['redirect_uris'][0]
        )
        
        # Get authorization response
        flow.fetch_token(
            authorization_response=request.url,
            state=state
        )
        
        # Get credentials
        credentials = flow.credentials
        
        # Get user info from ID token
        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            requests.Request(),
            GOOGLE_CLIENT_ID
        )
        
        # Clear OAuth state from session
        session.pop('oauth_state', None)
        session.pop('oauth_config', None)
        session.modified = True
        
        return {
            'email': id_info['email'],
            'name': id_info.get('name', ''),
            'sub': id_info['sub']
        }
    except Exception as e:
        logger.error(f"Error handling callback: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return None

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function 