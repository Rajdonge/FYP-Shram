from django.urls import path
from .views import UserRegistrationView, UserLoginView, UserLogoutView, UserProfileView, UserUpdateProfileView, UserChangePasswordView, SendPasswordResetEmailView, UserPasswordResetView, ProfilePictureView, FamilyDetailView, WorkInformationView, DocumentsView, initiate_payment, callback, ApplicationSubmissionView, SavePayment

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('logout/', UserLogoutView.as_view(), name='logout'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('update-profile/', UserUpdateProfileView.as_view(), name='update-profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>', UserPasswordResetView.as_view(), name='reset-password'),
    path('profile-pic/', ProfilePictureView.as_view(), name='profile-pic'),
    path('family-details/', FamilyDetailView.as_view(), name='family-details'),
    path('work-info/', WorkInformationView.as_view(), name='work-info'),
    path('documents/', DocumentsView.as_view(), name='documents'),
    path('initiate-payment/', initiate_payment, name='initiate_payment'),
    path('callback/', callback, name='callback'),
    path('savepayment/', SavePayment.as_view(), name='savepayment'),
    path('submit-application/', ApplicationSubmissionView.as_view(), name='submit-application'),

]