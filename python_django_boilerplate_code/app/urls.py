"""App urls"""
from django.urls import path
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions
from rest_framework_simplejwt.views import TokenRefreshView
from .views import CreateUser,ProfileView,AuthenticateUser,ChangePassword
from .views import GetUserById,GetAllUsers,LogoutAllView


SchemaView = get_schema_view(
   openapi.Info(
      title="User API",
      default_version='v1',
      description="User related all API's",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path(r'create_user/', CreateUser.as_view(),name='createuser'),
    path(r'authenticate_user/', AuthenticateUser.as_view(),name='authenticate_user'),
    path(r'changepassword/', ChangePassword.as_view(),name='changepassword'),
    path(r'getusers/', GetAllUsers.as_view(),name='getusers'),
    path(r'logout/', LogoutAllView.as_view(),name='logout'),
    path(r'refresh/', TokenRefreshView.as_view(),name='refresh'),
    path(r'getusersbyid/<int:pk>', GetUserById.as_view(),name='getusersbyid'),
    path(r'profile', ProfileView.as_view(),name='profile'),
    path(r'swagger/',SchemaView.with_ui('swagger',cache_timeout=0),name='schema-swagger-ui'),
    path(r'redoc/',SchemaView.with_ui('redoc', cache_timeout=0),name='schema-redoc'),
]