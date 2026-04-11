from google.oauth2 import id_token
from google.auth.transport import requests
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed

class GoogleAuthHelper:
    """Helper class to validate Google ID tokens."""

    @staticmethod
    def validate_google_id_token(token):
        """
        Validates a Google ID token and returns the user information.
        """
        try:
            # Specify the CLIENT_ID of the app that accesses the backend:
            # Verify the token
            id_info = id_token.verify_oauth2_token(
                token, 
                requests.Request(), 
                getattr(settings, 'GOOGLE_OAUTH2_CLIENT_ID', None)
            )

            # Check if token is issued by trusted source
            if id_info['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise AuthenticationFailed('Wrong issuer.')

            return id_info
        except ValueError as e:
            # Invalid token
            raise AuthenticationFailed(f'The token is either invalid or has expired: {str(e)}')
