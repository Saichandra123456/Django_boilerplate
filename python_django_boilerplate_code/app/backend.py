from django.contrib.auth.backends import ModelBackend
from rest_framework.exceptions import AuthenticationFailed,PermissionDenied
from .models import User

class EmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
                raise AuthenticationFailed("Email is not valid")
        else:
            if user.check_password(password):
                return user
            raise PermissionDenied("Password is not valid")