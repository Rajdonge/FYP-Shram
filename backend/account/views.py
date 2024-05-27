from rest_framework.views import APIView
from .serializers import UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer, UserUpdateProfileSerializer, UserChangePasswordSerializer, SendPasswordResetEmailSerializer, UserPasswordResetSerializer, ProfilePictureSerializer, FamilyDetailSerializer, WorkInformationSerializer, DocumentsSerializer, PaymentSerializer, ApplicationSerializer
from .models import FamilyDetailModel, ProfilePicModel, WorkInformationModel, DocumentsModel, Payment, Application
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse
import requests
import json
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import permission_classes

from django.contrib.auth import authenticate

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.decorators import login_required
from rest_framework.decorators import api_view

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

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def initiate_payment(request):
    user = request.user  # Get authenticated user
    print("User: ", user)
    
    # Extract data from request
    return_url = request.data.get('return_url')
    website_url = request.data.get('website_url')
    amount = request.data.get('amount')
    purchase_order_id = request.data.get('purchase_order_id')
    purchase_order_name = request.data.get('purchase_order_name')
    customer_info = request.data.get('customer_info', {})
    
    # Additional data for authentication
    auth_key = 'live_secret_key_68791341fdd94846a146f0457ff7b455'
    headers = {'Authorization': f'Key {auth_key}', 'Content-Type': 'application/json'}
    
    # Construct payload
    payload = {
        "return_url": return_url,
        "website_url": website_url,
        "amount": amount,
        "purchase_order_id": purchase_order_id,
        "purchase_order_name": purchase_order_name,
        "customer_info": customer_info
    }
    
    # Make request to Khalti API
    response = requests.post('https://a.khalti.com/api/v2/epayment/initiate/', json=payload, headers=headers)
    data = response.json()
    
    return Response(data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def callback(request):
    # Get the authenticated user (assuming the request contains the user's token)
    user = request.user
    print("User: ", user)
    
    # Extract parameters from the callback URL
    pidx = request.GET.get('pidx')
    total_amount = request.GET.get('total_amount')
    purchase_order_id = request.GET.get('purchase_order_id')
    purchase_order_name = request.GET.get('purchase_order_name')
    status = request.GET.get('status')
    
    # Log parameters for debugging
    print("pidx:", pidx)
    print("status:", status)
    
    
     # Return a successful response
    response_data = {
            'message': 'Callback processed successfully',
            'pidx': pidx,
            'status': status,
        }
    return Response(response_data)
    
    # If the payment was not successful, return an error response
    response_data = {
        'message': 'Payment failed',
        'pidx': pidx,
        'status': status,
    }
    return Response(response_data, status=status.HTTP_400_BAD_REQUEST)

class SavePayment(APIView):
    permission_classes=[IsAuthenticated]
    
    def get(self, request):
        user = request.user
        payments = Payment.objects.filter(user=user)
        serializer = PaymentSerializer(payments, many=True)
        return Response(serializer.data)


    def post(self, request):
        user = request.user
        serializer = PaymentSerializer(data=request.data, context={'user': user})
        if serializer.is_valid():
            serializer.save()
            return Response({'msg': 'Submitted successfully.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    
class ApplicationSubmissionView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            user = request.user
            application = Application.objects.get(user=user)
            serializer = ApplicationSerializer(application)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Application.DoesNotExist:
            # Return default values when application is not found
            default_data = {'application_status': 'Unsubmit', 'date_of_submission': None}
            return Response(default_data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        try:
            user = request.user
            application, created = Application.objects.get_or_create(user=user)

            # Check the current application status and update accordingly
            if application.application_status == 'Unsubmit':
                application.application_status = 'Submitted'
            elif application.application_status == 'Rejected':
                application.application_status = 'Resubmitted'

            elif application.application_status == 'Approved':
                application.application_status == 'Submitted'

            application.save()
            serializer = ApplicationSerializer(application, context={'user': user})
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Application.DoesNotExist:
            return Response({"error": "Application not found for this user"}, status=status.HTTP_404_NOT_FOUND)
        

        
            