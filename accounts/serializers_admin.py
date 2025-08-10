# accounts/serializers_admin.py
from rest_framework import serializers
from .models import CustomUser, Package

class MiniUserSerializer(serializers.ModelSerializer):
    id = serializers.CharField(source='pk')
    name = serializers.SerializerMethodField()
    joined_at = serializers.DateTimeField(source='date_joined')
    status = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'name', 'email', 'role', 'joined_at', 'status']

    def get_name(self, obj):
        return obj.username or obj.email.split('@')[0]

    def get_status(self, obj):
        return 'active' if obj.is_active else 'inactive'



class MiniUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'username', 'email', 'role', 'date_joined')

class MiniPackageSerializer(serializers.ModelSerializer):
    subscribers = serializers.IntegerField(read_only=True)
    class Meta:
        model = Package
        fields = (
            'id', 'name', 'price_monthly',
            'minutes_inbound_limit', 'minutes_outbound_limit', 'minutes_total_limit',
            'agents_allowed', 'analytics_access', 'features', 'is_active',
            'created_at', 'subscribers',
        )
        read_only_fields = ('created_at', 'subscribers')

class PackageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Package
        fields = (
            'id', 'name', 'price_monthly',
            'minutes_inbound_limit', 'minutes_outbound_limit', 'minutes_total_limit',
            'agents_allowed', 'analytics_access', 'features', 'is_active',
            'created_at',
        )
        read_only_fields = ('created_at',)

    def validate(self, attrs):
        """
        If minutes_total_limit > 0, we ignore inbound/outbound (or you can enforce mutual exclusion).
        """
        total = attrs.get('minutes_total_limit', getattr(self.instance, 'minutes_total_limit', 0))
        if total and total > 0:
            # optional normalization
            attrs['minutes_inbound_limit'] = attrs.get('minutes_inbound_limit', 0) or 0
            attrs['minutes_outbound_limit'] = attrs.get('minutes_outbound_limit', 0) or 0
        return attrs
