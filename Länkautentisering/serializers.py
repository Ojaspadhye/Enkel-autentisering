from rest_framework import serializers
from .google_auth import GoogleAuthHelper

class GoogleSocialAuthSerializer(serializers.Serializer):
    auth_token = serializers.CharField()

    def validate_auth_token(self, auth_token):
        user_data = GoogleAuthHelper.validate_google_id_token(auth_token)
        try:
            user_data['sub']
        except:
            raise serializers.ValidationError('The token is invalid or expired. Please login again.')

        return user_data
