from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponse
from django.contrib.auth import authenticate
from .serializers import CustomTokenObtainPairSerializer
from django.contrib.auth import get_user_model
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth import get_user_model
from datetime import datetime, timedelta
from rest_framework.permissions import IsAuthenticated
from .utils.send_mail import send_html_email

# Correct import
# from rest_framework_simplejwt.authentication import JWTAuthentication

import os
import base64
import httpx
from django.http import JsonResponse
import json
import jwt
import os
from datetime import timedelta
from .tokens import account_activation_token


import uuid
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import default_token_generator
from django.http import JsonResponse
from .models import PendingSignup,CustomUser
from .tokens import account_activation_token ,generate_refresh_tokens,decode_login_token,generate_access_tokens,generate_new_access_tokens
from dotenv import load_dotenv
User = get_user_model()
load_dotenv()


@csrf_exempt
def register(request):
    if request.method == 'POST':
        # Load the request body and extract the data
        data = json.loads(request.body)
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')

        # Validate the input
        if not email or not username or not password:
            return JsonResponse({'error': 'Email, username, and password are required.'}, status=400)

        try:
            # Check if there's an existing entry with the same email in PendingSignup
            existing_signup = PendingSignup.objects.get(email=email)
            # If the entry exists, delete it and proceed to create a new one
            print(f"User with email {email} already exists. Deleting the existing record.")
            existing_signup.delete()
        except PendingSignup.DoesNotExist:
            # No existing record, we can proceed with creating a new PendingSignup
            pass

        # Create new PendingSignup object and store the registration data
        pending_signup = PendingSignup.objects.create(
            email=email,
            username=username,
            password=password  # Store the password in PendingSignup (usually for later use)
        )

        # Generate the activation token
        token = account_activation_token.make_email_token({'email': email, 'username': username, 'id': pending_signup.id})

        # Save the token to the PendingSignup record
        pending_signup.token = token
        pending_signup.save()

        # Generate the verification URL
        verification_url = f'{settings.FRONTEND_URL}/verify-email/{token}'

        # Send the email verification message
        mail_subject = 'Activate your account'
        template_name='accounts/verification_template.html'
        context = {
            'verification_url': verification_url
        }
        # message = f'Please confirm your email by clicking on the following link: {verification_url}'
        # send_mail(mail_subject, message, settings.DEFAULT_FROM_EMAIL, [email])
        send_html_email(mail_subject, template_name, context, email)


        # Return success message
        return JsonResponse({'message': 'Please check your email for the verification link.'}, status=200)




@csrf_exempt
def verifyUsername(request):
    # Parse incoming JSON data
    data = json.loads(request.body)
    username = data.get('username')

    if not username:
        return JsonResponse({'error': 'Username is required'}, status=400)

    # Check if the username exists in the User table
    try:
        user_exists = CustomUser.objects.filter(username=username).exists()
        
        if user_exists:
            return JsonResponse({'taken':True,'message': 'Username already exists'},status=200)
        else:
            return JsonResponse({'taken':False,'message': 'Username is available'}, status=200)
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
def resendEmailLink(request):
    data = json.loads(request.body)
    email = data.get('email')
    if not email :
        return JsonResponse({"error":"email is not provided"})
    
    try :
        user_verfied = CustomUser.objects.filter(email=email).exists()
        if user_verfied :
            return JsonResponse({"message":"email verified"},status=200)
        
        pending_signup = PendingSignup.objects.get(email=email)
        username= pending_signup.username
        token = account_activation_token.make_email_token({'email': email, 'username': username, 'id': pending_signup.id})

            
            # Generate the verification URL
        verification_url = f'{settings.FRONTEND_URL}/verify-email/{token}'

            # Send the email verification message
        mail_subject = 'Activate your account'
        template_name='accounts/verification_template.html'
        context = {
            'verification_url': verification_url
        }
            # message = f'Please confirm your email by clicking on the following link: {verification_url}'
            # send_mail(mail_subject, message, settings.DEFAULT_FROM_EMAIL, [email])
        send_html_email(mail_subject, template_name, context, email)

        return JsonResponse({"message":"email resent"},status=200)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)



@csrf_exempt
def SendpasswordRecoveryEmail(request):
    data = json.loads(request.body)
    email = data.get('email')
    if not email :
        print("Recovery email is not there")
        return JsonResponse({"error":"email is not provided"})
    
    try :
        user_verfied = CustomUser.objects.filter(email=email).exists()
        if user_verfied :
            token = account_activation_token.make_email_token({'email': email},password=True)
            recovery_url = f'{settings.FRONTEND_URL}/recover-password/{token}'
            # Send the email verification message
            mail_subject = 'Recover Your Password'
            template_name='accounts/recovery_password_template.html'
            context = {
                'verification_url': recovery_url
            }
                # message = f'Please confirm your email by clicking on the following link: {verification_url}'
                # send_mail(mail_subject, message, settings.DEFAULT_FROM_EMAIL, [email])
            send_html_email(mail_subject, template_name, context, email)
            print(f'Password recovery Email sent to {email}')
            return JsonResponse({"message":"email sent",'status':"410"},status=200)
        else:
            return JsonResponse({"message":"email not registered.",'status':"420"},status=200)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
def verifyEmailAvailable(request):
    data = json.loads(request.body)
    email = data.get('email')

    if not email:
        return JsonResponse({'error': 'email is required'}, status=400)

    # Check if the username exists in the User table
    try:
        email_exists = CustomUser.objects.filter(email=email).exists()
        
        if email_exists:
            return JsonResponse({'taken':True,'message': 'email already exists'},status=200)
        else:
            return JsonResponse({'taken':False,'message': 'email is available'}, status=200)
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def checkExpiryVerificationLink(request,token):
    try:
        # Decode the token to check if it's valid and expired
        payload = account_activation_token.decode_email_token(token)
        email = payload['email']
        print(f'verifyu 122345 : {email}')

        # If token is valid, return expired = False
        return JsonResponse({"expired": False,'email':email}, status=200)

    except ValueError as e:
        # If token is expired or invalid, handle error
        if str(e) == "The token has expired.":
            return JsonResponse({"expired": True}, status=200)  # 410 for Gone (expired)
        else:
            return JsonResponse({"expired": True ,"invalid":True}, status=200)  # 404 if token is invalid
        

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json

@csrf_exempt
def PasswordChangeWithToken(request, token):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests allowed.'}, status=405)

    try:
        data = json.loads(request.body)
        new_password = data.get('password')

        if not new_password or len(new_password) < 8:
            return JsonResponse({'error': 'Password must be at least 8 characters.'}, status=400)

        # Decode email from token
        decoded = account_activation_token.decode_email_token(token)
        email = decoded.get('email')

        if not email:
            print("email is not extracted")
            return JsonResponse({'error': 'Invalid or expired token.'}, status=400)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return JsonResponse({'error': 'User not found.'}, status=404)

        # Set new password and save
        user.set_password(new_password)
        user.save()

        return JsonResponse({'success': 'Password changed successfully.',"OK":True})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)




from django.contrib.auth import login
from django.http import JsonResponse
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.models import User
from .models import PendingSignup
from .tokens import account_activation_token  # Import your token utility
from django.db import IntegrityError

from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.db import IntegrityError  # Correct import for IntegrityError
from .models import PendingSignup
from .tokens import account_activation_token
import jwt

@csrf_exempt
def verify_email(request, token):
    try:
        # Decode the JWT token to get the user data
        user_data = account_activation_token.decode_email_token(token)
        print(f'user data is : {user_data}')
        id = user_data['id']

        try:
            # Fetch the PendingSignup object using the ID from the decoded token
            pending_signup = PendingSignup.objects.get(id=id)
            print(f"pending_signup is : {pending_signup}")

            # User = get_user_model()

            # Check if the username already exists in the CustomUser model (i.e., in User table)
            if CustomUser.objects.filter(username=pending_signup.email).exists():
                # If username exists in the User model, the user is already registered
                return JsonResponse({'message': 'User already verified or username already taken.'}, status=200)

            # Verify if the decoded data matches the PendingSignup data
            if user_data['email'] == pending_signup.email and user_data['username'] == pending_signup.username:
                # Now create the user from the pending signup
                user = CustomUser.objects.create_user(
                    email=pending_signup.email,
                    username=pending_signup.username,
                    password=pending_signup.password,
                    is_verified=True
                )
                print("user added in user model")

                # Optionally, delete the PendingSignup record after successful registration
                pending_signup.delete()

                print("user deleted from pendingsignup model")


                # Log the user in (optional)
                # login(request, user)

                return JsonResponse({'message': 'Registration successful, and your email is verified.'}, status=200)

            else:
                return JsonResponse({'error': 'Invalid verification link.'}, status=400)

        except PendingSignup.DoesNotExist:
            # If PendingSignup does not exist, return that the user is already verified
            return JsonResponse({'message': 'User already verified.'}, status=200)

    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'Token expired'}, status=420)
    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'Invalid Token'}, status=421)

    except IntegrityError as e:
        # Log and handle IntegrityError, if the error persists
        print(f"IntegrityError occurred: {str(e)}")  # For debugging the IntegrityError
        return JsonResponse({'error': 'IntegrityError: Duplicate entry or conflict.'}, status=400)

    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)



    # except PendingSignup.DoesNotExist:
    #     return JsonResponse({'error': 'User does not exist.'}, status=400)

    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)
    
import json
from django.contrib.auth import authenticate
from django.http import JsonResponse
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings

# @csrf_exempt
# def login(request):
#     if request.method == 'POST':
#         data = json.loads(request.body)
#         email = data.get('email')
#         password = data.get('password')

#         # Check if email and password are provided
#         if not email or not password:
#             return JsonResponse({'error': 'Email and password are required'}, status=400)

#         # Authenticate user
#         user = authenticate(request, email=email, password=password)

#         if user is not None:
#             # Generate the refresh token

#             refresh_token = generate_refresh_tokens(user)
#             access_token = generate_access_tokens(user)
    

#             # Set the access token with expiration time

#             # Prepare the response body
#             response_data = {
#                 'token': str(access_token),  # Access token sent in the response body
#                 'user': {
#                     'name': user.username,
#                     'email': user.email,
#                     'role': user.role,
#                 },
#             }

#             # Calculate the refresh token's lifetime (in seconds)
#             refresh_lifetime = int(timedelta(days=7).total_seconds())

#             # Prepare the response object
#             response = HttpResponse(
#                 JsonResponse(response_data).content,
#                 content_type="application/json"
#             )

#             # Set the refresh token as an HTTP-only cookie with 7 days expiration
#             response.set_cookie(
#                 key='refresh_token',  # Cookie name
#                 value=str(refresh_token),  # Refresh token value
#                 httponly=True,  # Make sure cookie is HTTP-only and not accessible via JavaScript
#                 secure=True,  # Ensure cookie is only sent over HTTPS (use False for local development)
#                 samesite='None',  # Use Lax for cross-site requests
#                 max_age=refresh_lifetime,  # Set the expiration time for cookie in seconds (7 days)
#                 expires=(datetime.utcnow() + timedelta(days=7)).strftime("%a, %d-%b-%Y %H:%M:%S GMT"),  # Set explicit expiry date
#                 path='/'
#             )

#             # Return the response
#             return response

#         else:
#             return JsonResponse({'error': 'Invalid email or password',"status":"402"}, status=200)
    
#     return JsonResponse({'error': 'Only POST method is allowed'}, status=405)






# def decode_jwt_token(token):
#     try:
#         # Decode the token using the secret key
#         decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
#         return decoded_token
#     except jwt.ExpiredSignatureError:
#         return None  # Token has expired
#     except jwt.InvalidTokenError:
#         return None  # Invalid token



from datetime import datetime, timedelta, timezone
from django.http import JsonResponse
from django.conf import settings
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response

# from .serializers_auth import CustomTokenObtainPairSerializer

REFRESH_COOKIE_NAME = 'refresh_token'
REFRESH_COOKIE_PATH = '/'
# If your Next app is on a different domain, you need SameSite=None and secure=True (https)
REFRESH_COOKIE_SAMESITE = 'None'   # use 'Lax' if same-site
REFRESH_COOKIE_SECURE = True       # False in local http dev; True in https/prod
REFRESH_COOKIE_HTTPONLY = True

def _set_refresh_cookie(response: JsonResponse, refresh: str):
    # set expiry to match SIMPLE_JWT.REFRESH_TOKEN_LIFETIME
    max_age = int(settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds())
    # expires=datetime.now(timezone.utc)+settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']
    expires = (datetime.now(timezone.utc) + settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'])
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=str(refresh),
        # max_age=max_age,
        expires=expires,
        path=REFRESH_COOKIE_PATH,
        secure=REFRESH_COOKIE_SECURE,
        httponly=REFRESH_COOKIE_HTTPONLY,
        samesite=REFRESH_COOKIE_SAMESITE,
    )
def _clear_refresh_cookie(response: JsonResponse):
    # expire cookie in the past (your earlier preference)
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value='',
        expires='Thu, 01 Jan 1970 00:00:00 GMT',
        path=REFRESH_COOKIE_PATH,
        secure=REFRESH_COOKIE_SECURE,
        httponly=REFRESH_COOKIE_HTTPONLY,
        samesite=REFRESH_COOKIE_SAMESITE,
    )

# def _clear_refresh_cookie(response: JsonResponse):
#     # Best practice: delete_cookie (handles Max-Age=0)
#     response.delete_cookie(
#         key=REFRESH_COOKIE_NAME,
#         path=REFRESH_COOKIE_PATH,
#         samesite=REFRESH_COOKIE_SAMESITE,
#     )

class LoginView(TokenObtainPairView):
    """
    POST { email, password }
    -> sets refresh cookie
    -> returns { token: <access>, user: {...} }
    -> on invalid creds, returns { status: "402", error: ... } with 200
    """
    permission_classes = [AllowAny]
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            validated = serializer.validated_data     # has 'access' and 'refresh'
            access = validated.get('access')
            refresh = validated.get('refresh')
            user_payload = validated.get('user')

            body = {'token': access, 'user': user_payload}
            resp = JsonResponse(body, status=200)
            if refresh:
                _set_refresh_cookie(resp, str(refresh))
            return resp

        except Exception:
            # keep your existing frontend logic (toast on status "402")
            return JsonResponse(
                {'status': '402', 'error': 'Invalid email or password'},
                status=200
            )


class RefreshAccessTokenView(TokenRefreshView):
    """
    POST {} (no body)
    Reads refresh token from HTTP-only cookie and returns:
      - success: { "token": "<new access>" }  (HTTP 200)
      - no cookie: { "status": "425", "error": "No refresh token cookie" } (HTTP 200)
      - invalid/expired: { "status": "422", "error": "Invalid or expired refresh token" } (HTTP 200)
    """
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        cookie_refresh = request.COOKIES.get(REFRESH_COOKIE_NAME)
        if not cookie_refresh:
            return JsonResponse({'status': '425', 'error': 'No refresh token cookie'}, status=200)

        serializer = self.get_serializer(data={'refresh': cookie_refresh})
        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            # optionally clear the bad cookie
            resp = JsonResponse({'status': '422', 'error': 'Invalid or expired refresh token'}, status=200)
            _clear_refresh_cookie(resp)
            return resp

        access = serializer.validated_data['access']
        new_refresh = serializer.validated_data.get('refresh')

        # success body your frontend expects
        resp = JsonResponse({'token': access}, status=200)

        # if you ever enable ROTATE_REFRESH_TOKENS=True, update cookie here
        if new_refresh:
            _set_refresh_cookie(resp, str(new_refresh))

        return resp


class LogoutView(APIView):
    """
    POST {} -> (optional) blacklist refresh then clear cookie
    """
    permission_classes = [AllowAny]

    def post(self, request):
        cookie_refresh = request.COOKIES.get(REFRESH_COOKIE_NAME)
        # If you enabled token_blacklist app:
        # if cookie_refresh:
        #     try:
        #         token = RefreshToken(cookie_refresh)
        #         token.blacklist()
        #     except Exception:
        #         pass
        response = JsonResponse({'status': 'OK', 'message': 'Logged out'})
        _clear_refresh_cookie(response)
        return response



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_data(request):
    user = request.user
    return Response({
        'name': user.username,
        'email': user.email,
        'role': user.role,
    })


# @csrf_exempt
# def get_user_data(request):
#     try:
#         # Get the token from the Authorization header
#         authorization_header = request.headers.get('Authorization', None)
        
#         if not authorization_header:
#             return JsonResponse({'error': 'Authorization header missing'}, status=400)
        
#         # Extract the token from 'Bearer <token>'
#         token = authorization_header.split(' ')[1]
        
#         # Decode and validate the JWT token
#         decoded_token = decode_login_token(token)

#         if decoded_token is None:
#             return JsonResponse({'error': 'Invalid or expired token'}, status=401)
        
#         token_expiry = datetime.utcfromtimestamp(decoded_token['exp'])
#         if token_expiry < datetime.utcnow():
#             return JsonResponse({"message":"access token expired","status":"420"})
        
#         # Retrieve user information from the decoded token
#         user_id = decoded_token.get('user_id')  # Access user_id from the decoded token

#         # Ensure user_id exists in the decoded token
#         if not user_id:
#             return JsonResponse({'error': 'User ID not found in token'}, status=401)

#         # Retrieve the user from the database using the user_id
#         try:
#             user = get_user_model().objects.get(id=user_id)
#         except get_user_model().DoesNotExist:
#             return JsonResponse({'error': 'User not found'}, status=404)

#         # Return user information (name, email, role)
#         return JsonResponse({
#             'name': user.username,
#             'email': user.email,
#             'role': user.role,
#         })

#     except Exception as e:
#         return JsonResponse({'error': str(e)}, status=500)


from datetime import datetime, timedelta
from django.http import JsonResponse


@csrf_exempt
def refresh_access_token(request):
    # Ensure the request is a POST request
    if request.method == 'POST':

        # Retrieve the refresh token from the HTTP-only cookie
        refresh_token = request.COOKIES.get('refresh_token', None)
        
        if not refresh_token:
            return JsonResponse({'error': 'Refresh token is missing from cookies.',"status":"425"}, status=200)

        try:
            # Decode the refresh token using your custom decoding function
            print(f'refresh_token : {refresh_token}')
            refresh_token_data = decode_login_token(refresh_token)
            id=refresh_token_data['user_id']

            # Check if the refresh token has expired
            token_expiry = datetime.utcfromtimestamp(refresh_token_data['exp'])
            if token_expiry < datetime.utcnow():
                print('refresh token expired')
                return JsonResponse({"message":"refresh token expired","status":"422"},status=200)
            
            
            # Generate a new access token using data from the refresh token
            access_token = generate_new_access_tokens(refresh_token_data)

            # Optionally, rotate the refresh token (uncomment to rotate)
            # refresh_token = generate_refresh_token(refresh_token_data)  # Generate a new refresh token (7-day expiration)
            # Set the new refresh token in cookies
            # response.set_cookie('refresh_token', refresh_token, max_age=timedelta(days=7), httponly=True, secure=True)

            # Return the new access token
            return JsonResponse({
                'token': str(access_token)
            })


        except Exception as e:
            print("execpption error",f'Invalid refresh token. Please log in again. : {e}')
           
            return JsonResponse({f'error': 'Invalid refresh token. Please log in again. : {e}'}, status=401)

        except Exception as e:
            # Catch any other unexpected errors
            return JsonResponse({'error': str(e)}, status=400)
    
    else:
        # Handle invalid request method
        return JsonResponse({'error': 'Only POST method is allowed.'}, status=405)

# @csrf_exempt
# def logout(request):
#     try:
#         # Prepare the response body to indicate logout success
#         response = JsonResponse({'status': 'OK', 'message': 'Logged out successfully'})

#         # Set the refresh_token cookie's expiration date to a past date (e.g., Jan 1, 1990)
#         past_date = datetime(1990, 1, 1)

#         # Expire the refresh_token cookie by setting expires to a past date
#         response.set_cookie(
#             'refresh_token',  # Cookie name
#             '',  # Clear the cookie value
#             expires=past_date,  # Set expiration to the past date
#             httponly=True,  # Make sure cookie is HTTP-only
#             secure=True,  # Secure flag for HTTPS (use False for local dev)
#             samesite='None',  # Set SameSite policy
#             path='/',  # Path to match where cookie is valid
#         )

#         # Return the response after expiring the cookie
#         return response

#     except Exception as e:
#         return JsonResponse({'error': str(e)}, status=500)
    





############################################
##########   HEYGEN ACCESS TOKEN ###########
############################################

@csrf_exempt
def HumeAccessToken(request):
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