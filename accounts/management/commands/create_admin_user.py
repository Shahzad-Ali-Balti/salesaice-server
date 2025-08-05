from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model  # This will fetch the custom user model
from django.db import IntegrityError

class Command(BaseCommand):
    help = 'Creates an admin user with username: admin, email: admin@gmail.com, and password: 12345678'

    def handle(self, *args, **kwargs):
        # Get the custom user model
        User = get_user_model()

        # Check if the user already exists
        if not User.objects.filter(username='admin').exists():
            try:
                # Create an admin user
                user = User.objects.create_user(
                    username='admin',
                    email='admin@gmail.com',
                    password='12345678'
                )
                user.is_staff = True  # Make the user a staff member (admin privileges)
                user.is_superuser = True  # Grant superuser privileges
                user.save()

                self.stdout.write(self.style.SUCCESS('Successfully created admin user'))
            except IntegrityError:
                self.stdout.write(self.style.ERROR('Admin user already exists'))
        else:
            self.stdout.write(self.style.WARNING('Admin user already exists'))
