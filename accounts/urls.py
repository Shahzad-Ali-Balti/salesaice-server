from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('user/data/',views.get_user_data,name='user-data'),
    path('hume-access-token/', views.accessToken, name='accessToken'),
]
