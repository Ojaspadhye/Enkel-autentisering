from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from django.core.cache import cache


def get_request_ip(requests):
    x_forward_for = requests.META.get("HTTP_X_FORWARD_FOR")
    if x_forward_for:
        ip = x_forward_for.split(',')[0].strip()
    
    else:
        ip = requests.META.get("REMOTE_ADDR")
    
    return ip or '0.0.0.0'


class OTPResendThrottle(UserRateThrottle):
    scope = "resend_otp"

    def can_resend_otp(requests):
        email = requests.data.get("email")
        ip = get_request_ip(requests)

        if not email:
            return False
        
        throttle_key = f"otp_resend:{email}:{ip}"

        current_count = cache.get(throttle_key, 0)

        MAX_LIMIT = 3 

        if current_count >= MAX_LIMIT:
            return False
        
        cache.set(throttle_key, current_count + 1, timeout=60)

        return True



class OTPVerificationThrottle(UserRateThrottle):
    scope = "verify_otp"

    def verify_otp(requests):
        email = requests.data.get("email")
        ip = get_request_ip(requests)
        purpose = requests.data.get("purpose")
        otp_input = requests.data.get("otp")

        if not email or not purpose or not otp_input:
            return False
        
        otp_key = f"otp:{email}:{purpose}"
        abuse_key = f"otp_abuse:{ip}"

        otp_data = cache.get(otp_key, {"otp": None, "attempts": 0})

        abuse_count = cache.get(abuse_key, 0)

        MAX_ABUSE = 20

        if abuse_count >= MAX_ABUSE:
            return False
        cache.set(abuse_key, abuse_count + 1, timeout=300)

        otp_data["attempts"] += 1

        MAX_ATTEMPTS_PER_OTP = 5
        if otp_data["attempts"] > MAX_ATTEMPTS_PER_OTP:
            cache.set(otp_key, otp_data, timeout=300)
            return False
        
        if otp_input == otp_data["otp"]:
            cache.delete(otp_key)
            cache.set(abuse_key, 0, timeout=300)
            return True
        

        cache.set(otp_key, otp_data, timeout=300)
        return False


class SignupThrottle(AnonRateThrottle):
    scope = "signup"


class LoginThrottle(AnonRateThrottle):
    scope = "login"


class AccessTokenThrottle(UserRateThrottle):
    scope = "access_token"


class CoreDataUpdateThrottle(UserRateThrottle):
    scope = "core_update"


class UpdateEmailThrottle(UserRateThrottle):
    scope = "change_email"


class PasswordChangeThrottle(UserRateThrottle):
    scope = "user_passwrod_update"


class AnonPasswordChangeThrottle(AnonRateThrottle): # to send the reset link while user logged out
    scope = "anon_password_update"