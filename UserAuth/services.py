import secrets
import logging
from django.db import transaction
from django.core.mail import send_mail
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from UserAuth.models import UserProfile, OTPVerification
from UserAuth.exceptions import OTPExpiredException, OTPInvalidException, AcountActiveException, UserInactiveException, MissingTokenException, InvalidTokenException
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.exceptions import TokenError

logger = logging.getLogger(__name__)


def _send_otp_email(email, otp):
    send_mail(
        subject="Your verification code",
        message=(
            f"Your verification code is: {otp}\n\n"
            f"It expires in 2 minutes.\n"
            "Never share this code with anyone.\n\n"
            "If you didn't request this, you can safely ignore this email."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        fail_silently=False,
    )


def _resend_otp_services(user, purpose):

    if not user:
        raise ValueError("User missing")
    

    OTPVerification.objects.filter(user=user, purpose=purpose).delete()
    new_otp = OTPVerification.objects.create_otp(user, purpose=purpose)

    try:
        _send_otp_email(user.email, new_otp.otp)
    except Exception as e:
        logger.error("Failed to send OTP | user_id=%s error=%s", user.pk, str(e))
        raise

    logger.info("Otp resent | email=%s user_id=%s", user.email, user.pk)
    return user


def _send_password_reset_email(email):
    send_mail(
        subject="This is about your reset password",
        message=(
            f"This is link for your reset password"
            f"Never share this code with anyone"
            f"If you didn't request this, you can safely ignore this email."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        fail_silently=False,
    )

def _send_user_coredata_email(email):
    send_mail(
        subject="User data Update",
        message=(
            f"Your core data was changed."
            f"If you made the change Ingnore this Mail."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        fail_silently=False,
    )

def send_password_change_email(user):
    send_mail(
        subject="Your password has been changed",
        message=(
            f"Hi {user.username},\n\n"
            "Your account password has just been changed.\n"
            "If you did not perform this action, please contact support immediately!"
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )

def sign_up_services(validated_data):
    with transaction.atomic():
        user = UserProfile.objects.create_user(
            username   = validated_data["username"],
            email      = validated_data["email"],
            password   = validated_data["password"],
            first_name = validated_data.get("first_name") or None,
            last_name  = validated_data.get("last_name") or None,
            is_active  = False,
        )
        otp_record = OTPVerification.objects.create_otp(user, purpose='signup')

    _send_otp_email(user.email, otp_record.otp)
    logger.info("Signup OTP dispatched | email=%s user_id=%s", user.email, user.pk)
    return {"message": "User is succesfully created"}


def signup_resend_otp_services(validated_data):
    user = validated_data["user"]
    purpose = "signup"

    return _resend_otp_services(user=user, purpose=purpose)


def reactivate_resend_otp_services(validated_data):
    user = validated_data["user"]
    purpose = "reactivate"

    return _resend_otp_services(user=user, purpose=purpose)


def deactivate_resend_otp_services(validated_data):
    user = validated_data["user"]
    purpose = "deactivate"

    return _resend_otp_services(user=user, purpose=purpose)


def password_reset_otp_services(validated_data):
    user = validated_data["user"]
    purpose = "password"

    return _resend_otp_services(user=user, purpose=purpose)


def validate_otp_activate_services(validated_data):
    user = validated_data["user"]
    otp_input = str(validated_data["otp"]).strip()

    otp_record = OTPVerification.objects.filter(
        user=user,
        otp__iexact=otp_input
    ).first()

    if otp_record is None:
        raise OTPExpiredException("OTP expired or invalid")

    db_otp = str(otp_record.otp).strip()

    if not secrets.compare_digest(db_otp, otp_input):
        raise OTPInvalidException("OTP mismatch")

    with transaction.atomic():
        if user.is_active:
            raise AcountActiveException()

        user.is_active = True
        user.save(update_fields=["is_active"])

        otp_record.delete()

    logger.info("Account activated | email=%s user_id=%s", user.email, user.pk)
    return {"message": "User is successfully activated"}


def login_services(validated_data):
    user = validated_data["user"]

    if user.is_active == False:
        raise UserInactiveException()
    
    refresh_token = RefreshToken.for_user(user)
    access_token = refresh_token.access_token

    return {
        "access_token": str(access_token),
        "refresh_token": str(refresh_token)
    }


def logout_services(validated_data):
    refresh_token = validated_data["refresh_token"]

    if not refresh_token:
        raise MissingTokenException()

    try:
        token = RefreshToken(refresh_token)
        jti = token['jti']

        outstanding_token = OutstandingToken.objects.filter(jti=jti).first()

        if not outstanding_token:
            raise InvalidTokenException("Token not recognized")
        
        if BlacklistedToken.objects.filter(token=outstanding_token).exists():
            raise InvalidTokenException("Token already blacklisted")

        token.blacklist()
    except TokenError:
        raise InvalidTokenException("Invalid or expired token")
    

# For now
def reset_password_services(validated_data):
    email = validated_data["email"]
    user = validated_data["user"]
    _send_password_reset_email(email)
    logger.info("password reset email dispatched | email=%s user_id=%s", user.email, user.pk)


def core_data_update_services(validated_data, user):
    if not user:
        raise ValueError("User not found")
    
    first_name = validated_data.get("first_name")
    last_name = validated_data.get("last_name")

    if first_name:
        user.first_name = first_name
    if last_name:
        user.last_name = last_name

    user.save()

    _send_user_coredata_email(email=user.email)
    
    return {"first_name": user.first_name, "last_name": user.last_name}


def refresh_accesstoken_services(validated_data):
    refresh_token_str = validated_data["refresh_token"]

    try:
        refresh_token = RefreshToken(refresh_token_str)

        new_access_token = str(refresh_token.access_token)
        return {
            "access_token": new_access_token
        }
    
    except TokenError:
        raise ValueError(f"Invalid or expired refresh token")


def request_deactivation_service(validated_data):
    user = validated_data["user"]
    purpose="deactivate"

    try:
        otp_record = OTPVerification.objects.create_otp(user, purpose=purpose)
        _send_otp_email(user.email, otp_record.otp)

        return {"message": "OTP sent to your email"}

    except Exception as e:
        raise ValueError(f"Failed to initiate deactivation: {str(e)}")


def deactivate_services(validated_data):
    user = validated_data["user"]
    otp_record = validated_data["otp_record"]

    otp_record.delete()

    user.is_active = False
    user.save()

    logger.info(
        "Account deactivated | email=%s user_id=%s",
        user.email,
        user.pk
    )

    return {"message": "User successfully deactivated"}


def request_reactivation_services(validated_data):
    user = validated_data["user"]
    purpose = "reactivate"

    try:
        otp_record = OTPVerification.objects.create_otp(user, purpose=purpose)
        _send_otp_email(user.email, otp_record.otp)

        return {"message": "OTP sent to your email"}
    
    except Exception:
        raise ValueError(f"Failed to initiate reactivation")


def reactivate_account_services(validated_data):
    user = validated_data["user"]
    otp_record = validated_data["otp_record"]

    
    user.is_active=True
    otp_record.delete()

    user.save()

    logger.info(
        "Account activated | email=%s user_id=%s",
        user.email,
        user.pk
    )
    
    return {"message": "User is reactivated"}



def email_change_service(validated_data):
    user = validated_data["user"]
    new_email = validated_data["new_email"]

    otp_record = OTPVerification.objects.create_otp(
        user=user,
        purpose="email"
    )

    _send_otp_email(user.email, otp=otp_record.otp)

    return {
        "message": f"OTP sent to {new_email}",
    }