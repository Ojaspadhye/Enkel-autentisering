from rest_framework.throttling import UserRateThrottle, AnonRateThrottle, SimpleRateThrottle
from django.core.cache import cache
import time

class IPThrottleManager:

    @staticmethod
    def get_request_ip(requests):
        x_forward_for = requests.META.get("HTTP_X_FORWARD_FOR")
        if x_forward_for:
            ip = x_forward_for.split(',')[0].strip()
        
        else:
            ip = requests.META.get("REMOTE_ADDR")
        
        return ip or '0.0.0.0'


class OTPResendThrottle:
    MAX_LIMIT = 3
    INTERVAL = 60

    def can_resend_otp(self, request):
        email = request.data.get("email")
        ip = IPThrottleManager.get_request_ip(request)

        if not email:
            return True

        throttle_key = f"otp_resend:{email}:{ip}"

        try:
            current_count = cache.incr(throttle_key)
        except ValueError:
            cache.set(throttle_key, 1, timeout=self.INTERVAL)
            return True

        if current_count == 1:
            cache.expire(throttle_key, self.INTERVAL)

        if current_count > self.MAX_LIMIT:
            return False


        return True
    

    def throttle_failure(self, requests):
        pass



class OTPVerificationThrottle:
    MAX_ABUSE = 20
    MAX_ATTEMPTS_PER_OTP = 5
    INTERVAL = 300

    def verify_otp(self, request):
        email = request.data.get("email").lower().strip()
        ip = IPThrottleManager.get_request_ip(request)
        purpose = request.data.get("purpose")
        otp_input = request.data.get("otp")

        if not email or not purpose or not otp_input:
            return False

        otp_key = f"otp:{email}:{purpose}"
        attempts_key = f"otp_attempts:{email}:{purpose}"
        abuse_key = f"otp_abuse:{ip}"

        abuse_count = cache.get(abuse_key, 0)
        if abuse_count >= self.MAX_ABUSE:
            return False

        otp_data = cache.get(otp_key)
        if not otp_data:
            return False
        
        otp_value = otp_data.get("otp") if isinstance(otp_data, dict) else otp_data

        attempts = cache.get(attempts_key, 0) + 1
        cache.set(attempts_key, attempts, timeout=self.EXPIRY)

        if attempts > self.MAX_ATTEMPTS_PER_OTP:
            cache.add(abuse_key, 0, timeout=self.EXPIRY)
            cache.incr(abuse_key)
            return False
        
        if str(otp_input) == str(otp_value):
            cache.delete_many([otp_key, attempts_key, abuse_key])
            return True
        
        return False
    
    
    def throttle_failure(self):
        pass

 

'''
Attack Pattern
1. Same IP + many emails
2. Different IPs + same pattern emails
3. Disposable email domains

Multi-Layer Identity
1. IP → stops burst from one machine
2. Email → stops repeated attempts on same email
3. IP + Email → stops targeted abuse

Recomended Keys
1. signup_ip:{ip}
2. signup_email:{email}
3. signup_combo:{ip}:{email}
'''
class SignupThrottle(SimpleRateThrottle):
    #scope = "signup"
    MAX_IP_ABUSE = 5
    MAX_EMAIL_ABUSE = 3
    MAX_COMBO_ABUSE = 2
    INTERVAL = 3600

    def can_signup(self, request):
        email = request.data.get("email").lower().split()
        ip = IPThrottleManager.get_request_ip(request)

        if not email or not ip:
            return True
        
        mapp = {
            'ip': {
                'key': f"signup_ip:{ip}",
                'limit': self.MAX_IP_ABUSE
            },
            'email': {
                'key': f"signup_email:{email}",
                'limit': self.MAX_EMAIL_ABUSE
            },
            'combo': {
                'key': f"signup_combo:{ip}:{email}",
                'limit': self.MAX_COMBO_ABUSE
            }
        }

        now = time.time()
        valid_historys = {}

        for label, data in mapp.items():  ## yoyo The labels has to do its job after this bit gets sorted out
            cache_key = data['key']
            limit = data['limit']

            history = cache.get(key=cache_key, default=[])

            while history and history[-1] <= now - self.INTERVAL:
                history.pop()


            if len(history) >= limit:
                return False
            
            valid_historys[cache_key] = history

        for cache_key, history in valid_historys.items():
            history.insert(0, now)
            cache.set(cache_key, history, self.INTERVAL)

        return True
    

    def throttle_failure(self):
        pass



'''
Attack Pattern
1. Same email, many passwords  by email i mean identifier as username_email is allowed
2. Same IP, many accounts
3. Distributed attack (botnet)

Key:
1. identifier: Brute force guessing the password
2. ip: spam signup from same account
3. email+ip: added security
'''
class LoginThrottle(AnonRateThrottle):
    #scope = "login"

    MAX_IP_ABUSE = 5
    MAX_IDENTIFIER_ABUSE = 3
    MAX_COMBO_ABUSE = 2
    INTERVAL = 300

    def can_login(self, request):
        identifier = request.data.get("username_email")
        ip = IPThrottleManager(request)
        password = request.data.get("password")
        
        if not password:
            return True  # serializer would test this bit
        
        if not identifier:
            return False  # Will be used in the bit
        
        mapp = {
            'ip': {
                'key': f"login_ip:{ip}",
                'limit': self.MAX_IP_ABUSE
            },
            'identifier': {
                'key': f"login_identifier:{identifier}",
                'limit': self.MAX_IDENTIFIER_ABUSE
            },
            'combo': {
                'key': f"login_combo:{ip}_{identifier}",
                'limit': self.MAX_COMBO_ABUSE
            }
        }

        now = time.time()
        valid_history = {}

        for labels, data in mapp.items():
            cache_key = data["key"]
            limit = data["limit"]

            history = cache.get(key=cache_key, default=[])

            while history and history[-1] <= now - self.INTERVAL:
                history.pop()

            if len(history) >= limit:
                return False
            
            valid_history["cache_key"] = history

        for cache_key, history in valid_history.items():
            history.insert(0, now)
            cache.set(cache_key, history, self.INTERVAL)

        return True



'''
Attack Pattern
1. stolen token abuse
'''
class AccessTokenThrottle(UserRateThrottle):
    scope = "access_token"


'''
Attack Pattern
1. spam DB writes
'''
class CoreDataUpdateThrottle(UserRateThrottle):
    scope = "core_update"


'''
Attack Pattern
1. email spam
2. verification abuse
'''
class UpdateEmailThrottle(UserRateThrottle):
    scope = "change_email"


'''
Attack Pattern
1. brute-force old password
'''
class PasswordChangeThrottle(UserRateThrottle):
    scope = "user_passwrod_update"


'''
Attack Pattern
1. spam reset emails
2. DoS via email flooding
'''
class AnonPasswordChangeThrottle(AnonRateThrottle): # to send the reset link while user logged out
    scope = "anon_password_update"