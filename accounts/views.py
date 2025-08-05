from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model
from .serializers import UserSerializer
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth import get_user_model
# Correct import
# from rest_framework_simplejwt.authentication import JWTAuthentication

import os
import base64
import httpx
from django.http import JsonResponse
import json
import jwt
import os
from dotenv import load_dotenv
User = get_user_model()
load_dotenv()

@csrf_exempt
def register(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')

        if not email or not username or not password:
            return JsonResponse({'error': 'Email, username, and password are required.'}, status=400)

        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email already exists'}, status=400)

        if User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'Username already exists'}, status=400)

        # Role is hardcoded as 'user'
        user = User.objects.create_user(email=email, username=username, password=password, role='admin')

        return JsonResponse({'message': 'User registered successfully'},status=200)



@csrf_exempt
def login(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')

        # Authenticate user
        user = authenticate(request, email=email, password=password)

        if user is not None:
            # Generate the default refresh token
            refresh = RefreshToken.for_user(user)

            # Add additional custom claims to both access and refresh tokens
            refresh_payload = {
                'name': user.username,
                'email': user.email,
                'role': user.role,
            }
            secret_key=settings.SECRET_KEY
            # Encode the access token manually with custom claims
            custom_access_token = jwt.encode(
                {**refresh_payload, **{'exp': refresh.access_token['exp']}},  # Add expiration from original token
                secret_key,  # Secret key for signing the JWT
                algorithm='HS256'  # You can choose any algorithm (e.g., RS256 if using RSA keys)
            )

            # Encode the refresh token manually with custom claims
            custom_refresh_token = jwt.encode(
                {**refresh_payload, **{'exp': refresh['exp']}},  # Use the expiration time from the original refresh token
                secret_key,  # Secret key for signing the JWT
                algorithm='HS256'  # You can choose any algorithm (e.g., RS256 if using RSA keys)
            )

            # Return the custom JWT token and user data
            return JsonResponse({
                'refresh_token': custom_refresh_token,  # Return the custom refresh token with the additional claims
                'token': custom_access_token,  # Return the custom access token with the additional claims
                'user': {
                    'name': user.username,
                    'email': user.email,
                    'role': user.role,
                },
            })

        else:
            return JsonResponse({'error': 'Invalid email or password'}, status=401)


@csrf_exempt
def accessToken(request):
    if request.method == 'POST':
        # Reads `HUME_API_KEY` and `HUME_SECRET_KEY` from environment variables
        HUME_API_KEY = os.getenv('HUME_API_KEY')
        HUME_SECRET_KEY = os.getenv('HUME_SECRET_KEY')
        HUME_CONFIG_ID = os.getenv('HUME_CONFIG_ID')


        if not HUME_API_KEY or not HUME_SECRET_KEY:
            return JsonResponse({"error": "Missing HUME_API_KEY or HUME_SECRET_KEY"}, status=400)

        # Prepare authentication credentials
        auth = f"{HUME_API_KEY}:{HUME_SECRET_KEY}"
        encoded_auth = base64.b64encode(auth.encode()).decode()

        try:
            # Send the request to Hume API
            resp = httpx.post(
                url="https://api.hume.ai/oauth2-cc/token",
                headers={"Authorization": f"Basic {encoded_auth}"},
                data={"grant_type": "client_credentials"},
            )

            # Check if the request was successful
            if resp.status_code == 200:
                access_token = resp.json().get('access_token')
                # print(f"Access Token: {access_token}")
                return JsonResponse({"accessToken": access_token, "configId": HUME_CONFIG_ID}, status=200)

            # Handle API error response
            return JsonResponse({"error": "Failed to get access token", "details": resp.json()}, status=resp.status_code)

        except httpx.HTTPStatusError as e:
            # Handle HTTP error
            return JsonResponse({"error": "HTTP error", "details": str(e)}, status=500)
        except Exception as e:
            # Handle general exceptions
            return JsonResponse({"error": "An error occurred", "details": str(e)}, status=500)


def decode_jwt_token(token):
    try:
        # Decode the token using the secret
        decoded = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


@api_view(['GET'])
@permission_classes([IsAuthenticated])  # This still ensures that the user is authenticated
def get_user_data(request):
    try:
        # Get the refresh token from the Authorization header
        authorization_header = request.headers.get('Authorization', None)
        
        if not authorization_header:
            return JsonResponse({'error': 'Authorization header missing'}, status=400)
        
        # Extract the token from 'Bearer <token>'
        token = authorization_header.split(' ')[1]
        
        # Decode and validate the JWT token
        decoded_token = decode_jwt_token(token)

        if decoded_token is None:
            return JsonResponse({'error': 'Invalid or expired token'}, status=401)
        
        # Get user info from the decoded token
        user_id = decoded_token.get('user_id')
        
        # Retrieve the user from the database using the user_id
        user = get_user_model().objects.get(id=user_id)
        
        # Return user email and role
        return JsonResponse({
            'name': user.username,
            'email': user.email,
            'role': user.role,
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)