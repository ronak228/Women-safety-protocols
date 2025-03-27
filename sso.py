import os
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport import requests
from flask import session, url_for
from database import users
from datetime import datetime

# Google OAuth 2.0 configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = 'http://localhost:5000/google/callback'  # Update this in production

# OAuth 2.0 scopes
SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]

def get_google_auth_url():
    """Generate Google OAuth URL"""
    try:
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
            }
        )
        
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        
        # Store state in session for verification
        session['oauth_state'] = state
        
        return auth_url
    except Exception as e:
        print(f"Error generating Google auth URL: {str(e)}")
        return None

def handle_google_callback():
    """Handle Google OAuth callback"""
    try:
        # Get state from session
        state = session.get('oauth_state')
        if not state:
            return False, "Invalid OAuth state"
        
        # Create flow instance
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
            state=state
        )
        
        # Get authorization response
        flow.fetch_token(
            authorization_response=url_for('google_callback', _external=True)
        )
        
        # Get credentials
        credentials = flow.credentials
        
        # Get user info from ID token
        id_info = id_token.verify_oauth2_token(
            credentials.id_token, 
            requests.Request(), 
            GOOGLE_CLIENT_ID
        )
        
        # Extract user information
        email = id_info['email']
        name = id_info.get('name', '').split()
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
                'google_id': id_info['sub']
            }
            users.insert_one(user)
        
        # Set session variables
        session['login_verified'] = True
        session['user_email'] = email
        
        return True, "Login successful"
        
    except Exception as e:
        print(f"Error handling Google callback: {str(e)}")
        return False, str(e) 