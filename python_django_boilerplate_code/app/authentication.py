"""
JWTAuthentication configuration for the login and logout view.
"""
from rest_framework_simplejwt.authentication import JWTAuthentication as JWTA
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from rest_framework.exceptions import AuthenticationFailed

class JWTAuthentication(JWTA):
	"""This custom wrapper skip all the public urls from authentication."""
	def authenticate(self, request):
		# Call the authenticate method of the parent class to perform default JWT authentication
		res = super().authenticate(request)
		if res is None:
			return res
		user, token = res
		# Here we getting the latest token of user
		refersh_token = OutstandingToken.objects.filter(user=user).latest("id")
		# If refresh token exists in blaclisted token it will throw the AuthenticationFailed Exception
		if BlacklistedToken.objects.filter(token=refersh_token).exists():
			raise AuthenticationFailed('Your Token is Expired')
		return (user,token)

