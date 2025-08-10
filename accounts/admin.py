from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, PendingSignup

# Custom User Admin for CustomUser model
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('email', 'username', 'role', 'is_staff', 'is_verified')
    list_filter = ('role', 'is_verified')

    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        ('Permissions', {'fields': ('role', 'is_staff', 'is_verified', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'role', 'password1', 'password2', 'is_staff', 'is_verified')}
        ),
    )

    search_fields = ('email', 'username')
    ordering = ('email',)

# Register CustomUser with CustomUserAdmin
admin.site.register(CustomUser, CustomUserAdmin)

# Custom Admin for PendingSignup model
class PendingSignupAdmin(admin.ModelAdmin):
    list_display = ('email', 'username', 'created_at', 'is_verified')
    list_filter = ('is_verified',)
    search_fields = ('email', 'username')
    ordering = ('created_at',)

# Register PendingSignup with PendingSignupAdmin
admin.site.register(PendingSignup, PendingSignupAdmin)
