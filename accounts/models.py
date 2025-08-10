# accounts/models.py
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.conf import settings

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'admin')
        if not extra_fields.get('is_staff'):
            raise ValueError('Superuser must have is_staff=True.')
        if not extra_fields.get('is_superuser'):
            raise ValueError('Superuser must have is_superuser=True.')
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (('admin', 'Admin'), ('user', 'User'),)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')

    is_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)             # <-- ensure this exists
    date_joined = models.DateTimeField(default=timezone.now)

    objects = CustomUserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email


class PendingSignup(models.Model):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=255, unique=True)
    token = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    def __str__(self):
        return f"PendingSignup(id={self.id}, email={self.email}, username={self.username})"


# ---------- Admin/Subscription domain (stays in accounts app) ----------
# accounts/models.py (snippet)
from django.db import models

class Package(models.Model):
    name = models.CharField(max_length=120)
    price_monthly = models.DecimalField(max_digits=10, decimal_places=2)
    minutes_inbound_limit = models.PositiveIntegerField(default=0, blank=True, null=True)
    minutes_outbound_limit = models.PositiveIntegerField(default=0, blank=True, null=True)
    minutes_total_limit = models.PositiveIntegerField(default=0, blank=True, null=True)
    agents_allowed = models.PositiveIntegerField(default=1)
    analytics_access = models.BooleanField(default=False)
    features = models.JSONField(default=dict, blank=True)   # <- important: default=dict
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class Subscription(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='subscriptions')
    package = models.ForeignKey(Package, on_delete=models.PROTECT, related_name='subscriptions')

    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    auto_renew = models.BooleanField(default=True)

    minutes_used_inbound = models.PositiveIntegerField(default=0)
    minutes_used_outbound = models.PositiveIntegerField(default=0)

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['is_active']),
            models.Index(fields=['start_date']),
        ]

    def __str__(self):
        return f'{self.user.email} → {self.package.name}'
