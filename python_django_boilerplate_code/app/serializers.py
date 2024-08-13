"""
Serializer configuration for the app.
"""
from rest_framework import serializers
from .models import User
class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model.
    """
    class Meta:
        """
        Meta class for the User Serializer.
        """
        model = User
        fields = [ 'password', 'email', 'first_name', 'last_name', 'mobile']