"""
Admin configuration for the app.
"""
from django.contrib import admin
from .models import User
admin.site.register(User)
