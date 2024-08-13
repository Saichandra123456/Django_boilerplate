"""
API Calls
"""
import logging
from django.http import JsonResponse
from django.contrib.auth.hashers import make_password, check_password
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from app.serializers import UserSerializer
from .models import User
from .backend import EmailBackend

logger = logging.getLogger("django_service.service.views")

class CreateUser(APIView):
    """
    Create a new user   
    """

    @swagger_auto_schema(
        operation_id='Create User',
        request_body=UserSerializer)
    def post(self, request):
        """
        Create a new user
        """
        try:
            serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                data = serializer.validated_data
                email = data['email']
                password = data['password']
                password_hased = make_password(password) # Password Hashing
                # Email Validation checking weather email already exists aor not
                existing_user = User.objects.filter(email=email).first()
                if existing_user is not None:
                    return Response({'Message': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    # saving user plan password with hasing algorithme
                    user_obj=serializer.save(password = password_hased)
                    logger.info('User created successfully: %s', email)
                    return Response({'Message': 'User created successfully'}, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return JsonResponse({'Message': f"An error occurred due required feilds: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)


class AuthenticateUser(APIView):
    """
    Authenticate a user
    """
    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description=' email'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='password')
        }
    ))
    def post(self,request):
        """
        Authenticate a user
        """
        try:
            data = request.data
            email = data.get('email',None)
            password = data.get('password',None)
            # Here we are implemeting the custom authentication function. Checking the user details with email and password
            user=EmailBackend.authenticate(self,request,username=email,password=password)
            user_obj = User.objects.get(email = email)
            # custom token generation using the simple_jwt
            refresh = RefreshToken.for_user(user)
            logger.info('User Authenticated successfully: %s', email)
            return Response( {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'email':user_obj.email,
                "status":status.HTTP_200_OK
            })
        except Exception as e:
            return JsonResponse({'Message': f"An error occurred due required feilds: {str(e)}"}, status=status.HTTP_401_UNAUTHORIZED)

class ChangePassword(APIView):
    """
    Change Password
    """
    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='username or email'),
            'oldpassword': openapi.Schema(type=openapi.TYPE_STRING, description='Type old password'),
            'newpassword': openapi.Schema(type=openapi.TYPE_STRING, description='Type new password')
        }
    ))
    def post(self,request):
        """
        Change Password
        """
        try:
            data = request.data
            email = data['email']
            oldpassword = data['oldpassword']
            newpassword = data['newpassword']
            try:
                # Identifying the user with email
                user_obj = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            # checking user old password matched with the database record
            if not check_password(oldpassword, user_obj.password):
                return Response({'error': 'Invalid old password'}, status=status.HTTP_400_BAD_REQUEST)
            # Hashing the new password
            user_obj.password=make_password(newpassword)
            user_obj.save()
            logger.info('User changed password successfully: %s', email)
            return Response({'success': 'Password changed successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return JsonResponse({'Message': f"An error occurred due required feilds: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LogoutAllView(APIView):
    """
    Logout All
    """
    permission_classes = (IsAuthenticated,)
    def post(self, request):
        """
        Logout All
        """
        # Getting active token
        tokens = OutstandingToken.objects.filter(user=request.user)
        for token in tokens:
            # Blacklisting the active token
            BlacklistedToken.objects.get_or_create(token=token)
        return Response({'message':'Logout Successfully !'},status=status.HTTP_205_RESET_CONTENT)

class GetAllUsers(APIView):
    """
    Get All Users
    """
    permission_classes = (IsAuthenticated,)
    # Getting the all users
    @method_decorator(cache_page(60*1))
    def get(self, request):
        # id = request.user.id
        """
        API endpoint that fetch all users.
        """
        users_data = User.objects.all().order_by('-date_joined')
        user_serializer = UserSerializer(users_data, many=True, context={'request': request})
        logger.info('All useres data')
        return JsonResponse({"users": user_serializer.data})


class GetUserById(APIView):
    """
    Get User By Id
    """
    permission_classes = (IsAuthenticated,)
    # get user based on ID
    def get(self, request, pk):
        """
        API endpoint that fetch user by id.
        """
        queryset = User.objects.filter(id=pk)
        serializer_user = UserSerializer(queryset, many=True, context={'request': request})
        logger.info('User data based on id: %s',queryset)
        return JsonResponse({"users": serializer_user.data})


class ProfileView(APIView):
    """
    Get User Profile By Id
    """
    permission_classes = (IsAuthenticated, )
    @method_decorator(cache_page(60*1))
    def get(self, request):
        """
        API endpoint that fetch user profile.
        """
        data = {}
        data['email'] = request.user.email
        data['user_id'] = request.user.pk
        logger.info("User data %s", data)
        return Response(data)
