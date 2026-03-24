from django.urls import path
from UserAuth import views

urlpatterns = [
    path('signup/', views.signup_view, name="signup"), ##
    path('verify_otp/', views.verify_otp, name="veryfy_otp"), ##
    path('resend_otp/', views.resend_otp, name="resend_otp"), ##
    path('login/', views.login_view, name="login"), ##
    path('logout/', views.logout_view, name="logout"), ##
    path('reset_password/', views.reset_password, name="reset_password"), # When some one is not logged in 
    path('core_update/', views.core_data_update, name="update_profile"), ##
    path('security_notification/', views.security_notification, name="security_check"),
    path('refresh_access_token/', views.refresh_access_token, name="refresh_token"), ##
    path('deactivate_account_request/', views.request_deactivate_account, name="deactivate_account_request"), ##
    path('deacivation_verification/', views.deactivate_verification, name="deacivation_verification"), #
    path('reactivate_account_request/', views.reactivate_account, name="reactivate_account_request"), #
    path('reactivate_account_verification/', views.reactivate_verification, name="reactivate_verification"),
    path('auth_status/', views.check_auth_status, name="check_auth_status"),
    path('change_password/', views.change_password_auth, name="change_password"), # During person logged in
]