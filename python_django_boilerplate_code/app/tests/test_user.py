"""
Test cases for api calls
"""
import json
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase,APIClient
from rest_framework_simplejwt.tokens import AccessToken,RefreshToken
from ..models import User

class ApiUrlsTests(APITestCase):
    """
    Test api urls
    """
    create_url = reverse("createuser")
    login_url = reverse("authenticate_user")
    changepassword_url = reverse("changepassword")
    get_users_url = reverse("getusers")

    def setUp(self):
        self.user = User.objects.create_user(
            email='admin@gmail.com', password='admin', username='a')
        self.access_token = AccessToken.for_user(self.user)

    def tearDown(self):
        User.objects.all().delete()

    def test_create_user(self):
        """
        Ensure we can create a new account object.
        """
        url = '/create_user/'
        data = { 'password': '13456', 'email': 'test123@gmail.com',
                'first_name': 'narsimha', 'last_name': 'ch', 'mobile': '9848022338'}

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(json.loads(response.content), {"Message": "User created successfully"})

    def test_create_user_with_existing_email(self):
        """
        Ensure we cannot create a new account with existing email.
        """
        # First, create a user with the given email
        existing_user = User.objects.create_user(
            email='test123@gmail.com',
            password='12345',
            first_name='John',
            last_name='Doe',
            mobile='1234567890',
            username="narsimha"
        )
        # Now, try to create a new user with the same email
        url = reverse("createuser")
        data = {
            'password': '13456',
            'email': 'test123@gmail.com',
            'first_name': 'narsimha',
            'last_name': 'ch',
            'mobile': '9848022338',
            'username':'narsimha'
        }
        response = self.client.post(url, data, format='json')
        self.assertTrue(response.status_code == status.HTTP_400_BAD_REQUEST)
        self.assertEqual(json.loads(response.content), {'email':['user with this email already exists.']})

    def test_login_user(self):
        """
        Ensure we can login a new account object.
        """

        response = self.client.post(self.login_url, {"email":self.user.email,"password":'admin'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_login_user_with_incorrect_password(self):
        """
        Ensure we cannot login with an incorrect password.
        """
        response = self.client.post(self.login_url, {"email":self.user.email,"password":'1345'}, format='json')
        self.assertTrue(response.status_code == status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(json.loads(response.content), {'Message': 'An error occurred due required feilds: Password is not valid'})


    def test_change_password(self):
        """
        Ensure we can change the password object.
        """

        data={
            "email":self.user.email,
            "oldpassword":"admin",
            "newpassword":"12345"
        }
        response = self.client.post(self.changepassword_url, data, format='json')
        self.assertEqual(response.status_code,  status.HTTP_200_OK)

    def test_change_password_wrong_password(self):
        """
        Ensure we cannot change the password with wrong old password.
        """

        data={
            "email":self.user.email,
            "oldpassword":"wrongpassword",
            "newpassword":"12345"
        }
        response = self.client.post(self.changepassword_url, data, format='json')
        self.assertTrue(response.status_code == status.HTTP_400_BAD_REQUEST)
        self.assertEqual(json.loads(response.content), {'error':'Invalid old password'})



class UserLogoutTests(APITestCase):
    """
    Test api urls
    """
    def setUp(self):
        self.user = User.objects.create_user(
            email="test@test.com",
            password="password123",
            username = 'a'

        )
        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)

    def tearDown(self):
        User.objects.all().delete()

    def test_logout_user(self):
        """
        Ensure we can logout a user and their access token is blacklisted.
        """
        url = reverse("logout")
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + self.access_token)
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)

    def test_logout_user_with_invalid_token(self):
        """
        Ensure we cannot logout a user with an invalid access token.
        """
        url = reverse("logout")
        self.client.credentials(HTTP_AUTHORIZATION="Bearer invalid_token")
        response = self.client.post(url)
        self.assertTrue(response.status_code == status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(json.loads(response.content), {'detail':'Given token not valid for any token type','code':'token_not_valid','messages':[{'token_class':'AccessToken','token_type':'access','message':'Token is invalid or expired'}]})


class GetAllUsersAndBasedIdTests(APITestCase):
    """
    Test User apis
    """
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="test@test.com",
            password="password123",
            username = 'a'
        )
        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)

    def tearDown(self):
        User.objects.all().delete()

    def test_get_all_users_with_token(self):
        """
        Ensure we can get all users when authenticated with token.
        """
        url = reverse("getusers")
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + self.access_token)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_get_all_users_without_token(self):
        """
        Ensure we can't get all users without authentication token.
        """
        url = reverse("getusers")
        self.client.credentials(HTTP_AUTHORIZATION="Bearer invalid_token")
        response = self.client.get(url)
        self.assertTrue(response.status_code == status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(json.loads(response.content), {'detail':'Given token not valid for any token type','code':'token_not_valid','messages':[{'token_class':'AccessToken','token_type':'access','message':'Token is invalid or expired'}]})


    def test_get_user_by_id_with_token(self):
        """
        Ensure we can get a user by id when authenticated with token.
        """
        user_id = self.user.id
        url = reverse("getusersbyid", args=[user_id])
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + self.access_token)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


    def test_get_user_by_without_token(self):
        """
        Ensure we can't get a user by id without authentication token and without id.
        """
        user_id = self.user.id
        url = reverse("getusersbyid",args=[user_id])
        response = self.client.get(url)
        self.assertTrue(response.status_code == status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(json.loads(response.content), {'detail':'Authentication credentials were not provided.'})


    def test_get_user_profile_with_token(self):
        """
        Ensure we can get user profile when authenticated with token.
        """
        url = reverse("profile")
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + self.access_token)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_get_user_profile_without_token(self):
        """
        Ensure we can't get user profile without authentication token.
        """
        url = reverse("profile")
        response = self.client.get(url)
        self.assertTrue(response.status_code == status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(json.loads(response.content), {'detail':'Authentication credentials were not provided.'})
