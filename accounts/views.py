# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import authenticate, get_user_model
import jwt
from django.conf import settings

User = get_user_model()

class SignupView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        if User.objects.filter(username=username).exists():
            return Response({"error": "User already exists"}, status=400)
        user = User.objects.create_user(username=username, password=password)
        return Response({"msg": "User created successfully"})

class LoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(username=username, password=password)
        if user:
            token = jwt.encode({"id": user.id}, settings.SECRET_KEY, algorithm="HS256")
            return Response({"token": token})
        return Response({"error": "Invalid credentials"}, status=401)
