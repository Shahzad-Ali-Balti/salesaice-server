from django.urls import path,include
from . import views
from .views import LoginView,RefreshAccessTokenView,LogoutView
from .views_admin import PackageViewSet,AdminDashboardView
from rest_framework.routers import DefaultRouter
router = DefaultRouter()
router.register(r'admin/packages', PackageViewSet, basename='admin-packages')

urlpatterns = [
    path('register/', views.register, name='register'),
    path('check-username/', views.verifyUsername, name='verify-username'),
    path('check-email/', views.verifyEmailAvailable, name='email-available'),
    path('resend-verification-email/', views.resendEmailLink, name='resend-email'),
    path('send-password-recovery-email/', views.SendpasswordRecoveryEmail, name='send-password-recovery'),
    path('change-password-token/<token>/', views.PasswordChangeWithToken, name='passwrod-change-with-token'),
    path('check-verification-link/<token>/', views.checkExpiryVerificationLink, name='verification-link-expiry'),
    path('verify-email/<token>/', views.verify_email, name='verify_email'),
    path('login/', LoginView.as_view(), name='login'),
    path('refresh-access-token/', RefreshAccessTokenView.as_view(), name='refresh-token'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('user/data/',views.get_user_data,name='user-data'),


    ##ADMIN ACCESS ONLY##

    path('admin/dashboard/', AdminDashboardView.as_view(), name='admin-dashboard'),
    path('', include(router.urls)),

    ##ADMIN ACCESS ONLY##

    path('hume-access-token/', views.HumeAccessToken, name='accessToken'),
]
