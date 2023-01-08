from django.urls import path

from .views import (
    RegisterUserViews,
    LoginUser,
    VerifyOTP,
    ProfileDetails,
    SearchUsers,
    EditProfile,
    Logout
)


urlpatterns = [
    path('register/', RegisterUserViews.as_view()),
    path('login/', LoginUser.as_view()),
    path('verify_otp/', VerifyOTP.as_view(), name="verify_otp_login"),
    path('get_details/', ProfileDetails.as_view(), name="Get_Details"),
    path('search/', SearchUsers.as_view(), name="search_users"),
    path('edit_profile/', EditProfile.as_view(), name="edit_profile"),
    path('logout/', Logout.as_view(), name="logout-user")
]
