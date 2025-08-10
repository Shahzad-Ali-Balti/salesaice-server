import jwt
import datetime
from django.conf import settings  # You can store the JWT secret key in settings.py
from django.utils.http import urlsafe_base64_encode


class JWTTokenGenerator:
    def __init__(self, secret_key):
        self.secret_key = secret_key
    
    def make_email_token(self, user_data,password=False):
        """
        Create a JWT token containing the user data
        """
        if not password : 
            payload = {
                'email': user_data['email'],
                'username': user_data['username'],
                'id':user_data['id'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),  # Expiry time (1 hour)
                'iat': datetime.datetime.utcnow()  # Issued at time
            }
        if password :
             payload = {
                'email': user_data['email'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),  # Expiry time (1 hour)
                'iat': datetime.datetime.utcnow()  # Issued at time
            }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')  # Encoding the JWT token with the secret key

    def decode_email_token(self, token):
        """
        Decode the JWT token and return the user data
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("The token has expired.")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token.")

# Get the secret key from settings
JWT_SECRET_KEY = settings.SECRET_KEY  # Store this key securely in settings.py or env
account_activation_token = JWTTokenGenerator(secret_key=JWT_SECRET_KEY)



 # Secret key for JWT from settings

# Function to generate access and refresh tokens
def generate_access_tokens(user):
    # Define payload for the tokens
    payload_access = {
        'user_id': user.id,  # Include user_id
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),  # 1 hour expiration for access token
        'iat': datetime.datetime.utcnow(),  # Issued at time
    }

    
    # Generate the access token
    access_token = jwt.encode(payload_access, settings.SECRET_KEY, algorithm='HS256')

    # Generate the refresh token

    return access_token

def generate_new_access_tokens(user):
    # Define payload for the tokens
    payload_access = {
        'user_id': user['user_id'],  # Include user_id
        'username': user['username'],
        'email': user['email'],
        'role': user['role'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),  # 1 hour expiration for access token
        'iat': datetime.datetime.utcnow(),  # Issued at time
    }

    
    # Generate the access token
    access_token = jwt.encode(payload_access, settings.SECRET_KEY, algorithm='HS256')

    # Generate the refresh token

    return access_token

def generate_refresh_tokens(user):
    # Define payload for the tokens
   

    payload_refresh = {
       'user_id': user.id,  # Include user_id
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),  # 7 days expiration for refresh token
        'iat': datetime.datetime.utcnow(),  # Issued at time
    }

    # Generate the access token

    # Generate the refresh token
    refresh_token = jwt.encode(payload_refresh, settings.SECRET_KEY, algorithm='HS256')

    return  refresh_token

# Function to decode and verify the JWT
def decode_login_token(token):
    try:
        # Decode the token using the secret key
        decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        return decoded  # Returns the decoded payload (username, email, role, etc.)
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired'}
    except jwt.InvalidTokenError:
        return {'error': 'Invalid token'}
