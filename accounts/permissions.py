# accounts/permissions.py
from rest_framework.permissions import BasePermission

class IsSystemAdmin(BasePermission):
    def has_permission(self, request, view):
        u = request.user
        return bool(u and u.is_authenticated and getattr(u, 'role', '') == 'admin')
