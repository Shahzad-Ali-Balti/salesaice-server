from django.db import models

# Create your models here.
from django.db import models
from django.conf import settings

class Package(models.Model):
    name = models.CharField(max_length=120, unique=True)
    price_monthly = models.DecimalField(max_digits=8, decimal_places=2, default=0)
    minutes_inbound_limit = models.PositiveIntegerField(default=0)
    minutes_outbound_limit = models.PositiveIntegerField(default=0)
    minutes_total_limit = models.PositiveIntegerField(default=0)  # if you prefer a single cap
    agents_allowed = models.PositiveIntegerField(default=1)
    analytics_access = models.BooleanField(default=False)
    features = models.JSONField(default=dict, blank=True)  # e.g. {"campaigns": 3, "api_access": true}
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

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
