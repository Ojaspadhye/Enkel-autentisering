from django.shortcuts import render
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model

from .serializers import GoogleSocialAuthSerializer

User = get_user_model()

class GoogleSocialAuthView(GenericAPIView):
    serializer_class = GoogleSocialAuthSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        data = serializer.validated_data
        email = data.get('email')
        first_name = data.get('given_name', '')
        last_name = data.get('family_name', '')
        
        # We need a username, since it is required. We can use the email prefix or google sub
        username = data.get('email').split('@')[0] if email else data.get('sub')
        
        user = User.objects.filter(email=email).first()
        
        if not user:
            # Create user if it doesn't exist
            # Handle unique username constraint
            base_username = username
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1
                
            user = User.objects.create_user(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name
            )
            user.is_active = True
            user.save()
            
        # Generate JWT Tokens
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'email': user.email,
            'username': user.username,
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }, status=status.HTTP_200_OK)
