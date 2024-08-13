"""
Models configuration for the app.
"""
from django.db import models
from django.contrib.auth.models import AbstractUser
class User(AbstractUser):
    """
    Custom user model with additional fields for email and mobile.
    """
    email = models.EmailField(unique=True,max_length=255,blank=False)
    mobile = models.CharField(default=None, max_length=15, blank=True, null=True)
    username = models.CharField(max_length=150, unique=False)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
