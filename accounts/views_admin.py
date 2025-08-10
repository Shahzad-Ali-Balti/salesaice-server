# accounts/views_admin.py
from django.db import models
from django.db.models import Count
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
 # simple fake trend points to match frontend sparkline
import random
from .models import CustomUser, Package, Subscription
from .serializers_admin import MiniUserSerializer, MiniPackageSerializer, PackageSerializer
from .permissions import IsSystemAdmin

class AdminDashboardView(APIView):
    permission_classes = [IsAuthenticated, IsSystemAdmin]

    def get(self, request):
        total_users = CustomUser.objects.count()
        active_users = CustomUser.objects.filter(is_active=True).count()
        total_packages = Package.objects.count()

        # TODO: replace with real count from Call model once available
        calls_today = 0

        # Top packages by active subscribers
        top_qs = (
            Package.objects.filter(is_active=True)
            .annotate(subscribers=Count('subscriptions', filter=models.Q(subscriptions__is_active=True)))
            .order_by('-subscribers')[:3]
        )
        top_packages = MiniPackageSerializer(top_qs, many=True).data

        # 5 most recent users
        recent_users = MiniUserSerializer(CustomUser.objects.order_by('-date_joined')[:5], many=True).data

       
        def pts(n, base, spread):
            return [{'x': i, 'y': int(base + random.random()*spread)} for i in range(n)]

        payload = {
            'metrics': {
                'totalUsers': total_users,
                'activeUsers': active_users,
                'totalPackages': total_packages,
                'mrrUsd': 0,            # hook Stripe later
                'callsToday': calls_today,
                'churnRatePct': 0.0,    # compute when tracking cancels
            },
            'trends': {
                'mrr': pts(12, 14000, 6000),
                'calls': pts(14, 800, 700),
                'users': pts(12, 2000, 1200),
            },
            'recentUsers': recent_users,
            'topPackages': top_packages,
        }
        return Response(payload)


class PackageViewSet(viewsets.ModelViewSet):
    queryset = Package.objects.all().order_by('-created_at')
    serializer_class = PackageSerializer
    permission_classes = [IsAuthenticated, IsSystemAdmin]
    http_method_names = ['get','post','patch','put','delete','head','options']  # <- explicit

    # Debug hooks (remove when happy)
    def update(self, request, *args, **kwargs):
        print("UPDATE payload:", request.data)  # server console
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        print("PARTIAL_UPDATE payload:", request.data)  # server console
        kwargs['partial'] = True
        return super().partial_update(request, *args, **kwargs)
