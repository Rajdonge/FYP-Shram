from rest_framework.views import APIView
from .serializers import UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer, UserUpdateProfileSerializer, UserChangePasswordSerializer, SendPasswordResetEmailSerializer, UserPasswordResetSerializer, FamilyDetailSerializer
from .models import FamilyDetailModel
from rest_framework.response import Response
from rest_framework import status

from django.contrib.auth import authenticate

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'msg': 'User registered sucessfully.'}, status=status.HTTP_201_CREATED)
       

class UserLoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'token': token, 'msg': 'Login Successful.'}, status=status.HTTP_200_OK)
            else:
                return Response({'Error': 'Email or Password is not valid'})
            
        return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)
    
class UserLogoutView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            # Clear the access token from the client side
            # Assuming the client clears the token from local storage
            return Response({'message': 'Logout successful.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class UserUpdateProfileView(APIView):
    permission_classes = [IsAuthenticated]
    def patch(self, request):
        serializer = UserUpdateProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({'msg': 'Profile has been updated successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = UserChangePasswordSerializer(data = request.data, context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'Password changed successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class SendPasswordResetEmailView(APIView):
    def post(self, request):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Password reset link was sent, check your email'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserPasswordResetView(APIView):
    def post(self, request, uid, token):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'Password reset successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#Family Detail View
class FamilyDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        # Get existing FamilyDetailModel instance or create a new one
        family_data, created = FamilyDetailModel.objects.get_or_create(user=user)

        serializer = FamilyDetailSerializer(family_data, data=request.data, partial=True, context={'user': user})

        if serializer.is_valid():
            serializer.save()
            return Response({'msg': 'Family details saved successfully'})
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        user = request.user

        try:
            family_data = FamilyDetailModel.objects.get(user=user)
            serializer = FamilyDetailSerializer(family_data)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except FamilyDetailModel.DoesNotExist:
            return Response({'msg': 'Family details not found'}, status=status.HTTP_404_NOT_FOUND)

    def patch(self, request):
        user = request.user

        try:
            family_data = FamilyDetailModel.objects.get(user=user)
            serializer = FamilyDetailSerializer(family_data, data=request.data, partial=True, context={'user': user})

            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response({'msg': 'Family details successfully updated'}, status=status.HTTP_200_OK)
        except FamilyDetailModel.DoesNotExist:
            return Response({'msg': 'Family details not found'}, status=status.HTTP_404_NOT_FOUND)