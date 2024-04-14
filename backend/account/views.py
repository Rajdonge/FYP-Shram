from rest_framework.views import APIView
from .serializers import UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer, UserUpdateProfileSerializer, UserChangePasswordSerializer, SendPasswordResetEmailSerializer, UserPasswordResetSerializer, ProfilePictureSerializer, FamilyDetailSerializer, WorkInformationSerializer, DocumentsSerializer
from .models import FamilyDetailModel, ProfilePicModel, WorkInformationModel, DocumentsModel
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse

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
    
#Profile Picture View
class ProfilePictureView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user = self.request.user

            #Retreive the uploaded images
            profile_pic = request.FILES.get('profile_pic')

            #Create a new instance of Profile picture
            new_image = ProfilePicModel(
                user=user,
                profile_pic = profile_pic
            )
            new_image.save()

            return JsonResponse({'message': 'Profile pic uploaded successfully.'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def get(self, request):
        try:
            user = self.request.user
            profile_pic_info = ProfilePicModel.objects.get(user=user)

            return Response({
                'profile_pic': profile_pic_info.profile_pic.url if profile_pic_info.profile_pic else None
            })
        except ProfilePicModel.DoesNotExist:
            return Response({'message': 'Profile pic not found'}, status=400)
    
    def patch(self, request):
        user = self.request.user

        try:
            profile_pic_data = ProfilePicModel.objects.get(user=user)
            serializer = ProfilePictureSerializer(profile_pic_data, data=request.data, partial=True, context={'user': user})
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response({'msg': 'Profile picture changed successfully.'}, status=status.HTTP_200_OK)
        except ProfilePicModel.DoesNotExist:
            return Response({'msg': 'Profile picture not found'}, status=status.HTTP_404_NOT_FOUND)


        
            


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
        
    
#Work Information View
class WorkInformationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = WorkInformationSerializer(data=request.data, context={'user': request.user})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({'message': 'Work Information sent to backend successfully.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        user = request.user

        try:
            work_data = WorkInformationModel.objects.get(user=user)
            serializer = WorkInformationSerializer(work_data)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except WorkInformationModel.DoesNotExist:
            return Response({'msg': 'Work information not found'}, status=status.HTTP_404_NOT_FOUND)
    
    def patch(self, request):
        user = request.user

        try:
            work_data = WorkInformationModel.objects.get(user=user)
            serializer = WorkInformationSerializer(work_data, data=request.data, partial=True, context={'user': user})
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response({'msg': 'Work Information updated successfully.'}, status=status.HTTP_200_OK)
        except WorkInformationModel.DoesNotExist:
            return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)
        
#Documents View
class DocumentsView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user = self.request.user
            serializer = DocumentsSerializer(data=request.data, context={'user': user})
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response({'Documents uploaded successfully.'}, status=200)
            else:
                return Response(serializer.errors, status=400)
        except Exception as e:
            return Response({'error': str(e)}, status=500)
        
    def get(self, request):
        try:
            user = self.request.user
            documents = DocumentsModel.objects.get(user=user)

            return Response({
                'passport': documents.passport.url if documents.passport else None,
                'visa': documents.visa.url if documents.visa else None,
                'embassy_letter': documents.embassy_letter.url if documents.embassy_letter else None,
                'contract_paper': documents.contract_paper.url if documents.contract_paper else None,
                'driving_license': documents.driving_license.url if documents.driving_license else None
            })
        except DocumentsModel.DoesNotExist:
            return Response({'message': 'Documents not found.'}, status=404)

    def patch(self, request):
        try:
            user = self.request.user
            documents =DocumentsModel.objects.get(user=user)
            serializer = DocumentsSerializer(documents, data=request.data, partial=True, context={'user': user})
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response({'Documents updated successfully.'}, status=status.HTTP_200_OK)
        except DocumentsModel.DoesNotExist:
            return Response({'Documents not found.'}, status=status.HTTP_404_NOT_FOUND)
