from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from .serializers import UserSerializer
import os
import base64
import httpx
from django.http import JsonResponse
import json
from dotenv import load_dotenv
User = get_user_model()
load_dotenv()

@csrf_exempt
def register(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')

        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'User already exists'}, status=400)

        user = User.objects.create_user(email=email, password=password)
        return JsonResponse({'message': 'User registered successfully'})


@csrf_exempt
def login(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')

        user = authenticate(request, email=email, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            # Serialize user
            user_data = UserSerializer(user).data

            return JsonResponse({
                'token': access_token,
                'user': user_data,
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
