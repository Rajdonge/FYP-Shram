from django.urls import path
from .views import UserRegistrationView, UserLoginView, UserLogoutView, UserProfileView, UserUpdateProfileView, UserChangePasswordView, SendPasswordResetEmailView, UserPasswordResetView, FamilyDetailView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('logout/', UserLogoutView.as_view(), name='logout'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('update-profile/', UserUpdateProfileView.as_view(), name='update-profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>', UserPasswordResetView.as_view(), name='reset-password'),
    path('family-details/', FamilyDetailView.as_view(), name='family_details'),
]