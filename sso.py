from flask import url_for, session, redirect, request
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests
import os
from database import users
from datetime import datetime

# Google OAuth2 configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:5000/google/callback')

# OAuth2 flow configuration
SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]

def get_google_auth_url():
    """Generate Google OAuth2 authorization URL"""
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
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    
    session['state'] = state
    return authorization_url

def handle_google_callback():
    """Handle Google OAuth2 callback"""
    try:
        state = session['state']
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
        
        flow.fetch_token(
            authorization_response=request.url,
            redirect_uri=GOOGLE_REDIRECT_URI
        )
        
        credentials = flow.credentials
        id_info = id_token.verify_oauth2_token(
            credentials.id_token, 
            requests.Request(), 
            GOOGLE_CLIENT_ID
        )
        
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
                'is_verified': True,  # Google accounts are pre-verified
                'created_at': datetime.utcnow(),
                'auth_provider': 'google'
            }
            users.insert_one(user)
        
        # Set session
        session['login_verified'] = True
        session['user_email'] = email
        
        return True, "Login successful"
    except Exception as e:
        print(f"Google SSO error: {str(e)}")
        return False, str(e) 