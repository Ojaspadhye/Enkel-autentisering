from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from UserAuth.models import UserProfile, OTPVerification
from UserAuth.serializer import SignupSerializer, OTPVerifySerializer, OTPResendSerializer, LoginSerializer, PasswordResetSerializer, LogoutSerializer, CoreProfileUpdateSerializer, RefreshAccessTokenSerializer, DeactivateSerializer, ReactivateRequestSeializer
from UserAuth.services import sign_up_services, validate_otp_activate_services, resend_otp_services, login_services, logout_services, reset_password_services, core_data_update_services, refresh_accesstoken_services, request_deactivation_service, deactivate_services, request_reactivation_services, reactivate_account_services
import logging
from rest_framework_simplejwt.tokens import RefreshToken

# Create your views here.
logger = logging.getLogger(__name__)


@api_view(["POST"])
def signup_view(request):
    serializer = SignupSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    sign_up_services(serializer.validated_data)
    return Response(
        {"message": "A verification code has been sent to your email."},
        status=status.HTTP_201_CREATED,
    )


@api_view(["POST"])
def verify_otp(request):
    serializer = OTPVerifySerializer(
        data=request.data,
        context={"request": request}
    )
    serializer.is_valid(raise_exception=True)
    validate_otp_activate_services(serializer.validated_data)
    return Response(
        {"message": "The User activated"},
        status=status.HTTP_200_OK
    )


@api_view(["POST"])
def resend_otp(request):
    serializer = OTPResendSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    resend_otp_services(serializer.validated_data)
    return Response(
        {"message": "OTP Has been sent to your email"},
        status=status.HTTP_201_CREATED
    )


@api_view(["POST"])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    tokens = login_services(serializer.validated_data)
    return Response(tokens, status=status.HTTP_200_OK)


@api_view(["POST"])
def reset_password(request):
    serializer = PasswordResetSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    reset_password_services(serializer.validated_data)
    return Response(
        {"message": "Password reset link sent to the email"},
        status=status.HTTP_200_OK
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    serializer = LogoutSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    logout_services(serializer.validated_data)
    
    return Response(
        {"message": "User logged out"},
        status=status.HTTP_200_OK
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def core_data_update(request):
    serializer = CoreProfileUpdateSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = request.user
    response = core_data_update_services(serializer.validated_data, user)
      
    return Response(
        {
            "message": "Data updated successfully",
            "updated_data": response
        },
        status=status.HTTP_200_OK
    )



def security_notification():
    pass


@api_view(["POST"])
@permission_classes([AllowAny])
def refresh_access_token(request):
    serializer = RefreshAccessTokenSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    new_access_token = refresh_accesstoken_services(serializer.validated_data)
    return Response(new_access_token, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def request_deactivate_account(request):
    serializer = DeactivateSerializer(
        data=request.data,
        context={"request": request}
    )
    serializer.is_valid(raise_exception=True)

    response = request_deactivation_service(serializer.validated_data)

    return Response(response, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def deactivate_verification(request):
    serializer = OTPVerifySerializer(
        data=request.data,
        context={"request": request}
    )
    serializer.is_valid(raise_exception=True)

    response = deactivate_services(serializer.validated_data)

    return Response(response, status=status.HTTP_200_OK)


@api_view(["POST"])
def reactivate_account(request):
    serializer = ReactivateRequestSeializer(
        data=request.data,
        context={"request": request}
    )
    serializer.is_valid(raise_exception=True)

    response = request_reactivation_services(serializer.validated_data)

    return Response(response, status=status.HTTP_200_OK)


@api_view(["POST"])
def reactivate_verification(request):
    serializer = OTPVerifySerializer(
        data=request.data,
        context={"request": request}
    )
    serializer.is_valid(raise_exception=True)

    response = reactivate_account_services(serializer.validated_data)

    return Response(response, status=status.HTTP_200_OK)

    


def check_auth_status():
    pass


def change_password_auth():
    pass



