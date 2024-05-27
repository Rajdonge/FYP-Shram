from xml.dom import ValidationErr
from django.forms import ValidationError
from rest_framework import serializers

from account.utils import Util
from .models import User, ProfilePicModel, FamilyDetailModel, WorkInformationModel, DocumentsModel, Payment, Application
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator


#User Registration serializer
class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['email', 'name', 'date_of_birth', 'gender', 'address', 'contact', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    #validation email
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email address is already taken. Please try again.")
        return value

    #validation password
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')

        if password and password2 and password != password2:
            raise serializers.ValidationError("Password and confirm password do not match.")
        return attrs
        

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    


# User Login serializer
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email', 'password']

#User Profile serializer
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'date_of_birth', 'gender', 'address', 'contact']

#User Update Profile serializer
class UserUpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['name', 'email', 'date_of_birth', 'gender', 'address', 'contact']

#User Change Password serializer
class UserChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password and confirm password do not match.")
        user.set_password(password)
        user.save()
        return attrs
    
#Send Password Reset Email Serializer
class SendPasswordResetEmailSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email']
    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('Encoded uid', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password Reset token', token)
            link = 'http://192.168.1.118:5554/api/user/reset-password/'+uid+'/'+token
            print('Password Reset Link', link)

            #send Email
            body = 'Click the following link to reset your password '+ link
            data ={
                'subject': 'Reset your password',
                'body': body,
                'to_email': user.email
            }
            Util.send_email(data)

            return attrs
        else:
            raise ValidationErr('You are not a registered user.')
        
#User Password Reset Serializer
class UserPasswordResetSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    
    class Meta:
        model = User
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        uid = self.context.get('uid')
        token = self.context.get('token')
        
        if password != password2:
            raise serializers.ValidationError("Password and confirm password do not match.")

        try:
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError('Token is not valid or expired')

            user.set_password(password)
            user.save()
        except (DjangoUnicodeDecodeError, User.DoesNotExist):
            raise serializers.ValidationError('Invalid uid or token')

        return attrs
    
#Profile Picture Serializer
class ProfilePictureSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProfilePicModel
        fields = ['profile_pic']

    def create(self, validated_data):
        user = self.context.get('user')
        profile_data = ProfilePicModel.objects.create(user=user, **validated_data)
        return profile_data
    

#Family Detail Serializer
class FamilyDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = FamilyDetailModel
        fields = ['father_name', 'mother_name', 'mobile_number']

    def create(self, validated_data):
        user = self.context.get('user')
        family_data = FamilyDetailModel.objects.create(user=user, **validated_data)
        return family_data
    
# Work Information Serializer
class WorkInformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkInformationModel
        fields = ['applicationType', 'passport_no', 'country', 'company', 'profession', 'salary']

    def create(self, validated_data):
        user = self.context.get('user')
        work_information = WorkInformationModel.objects.create(user=user, **validated_data)
        return work_information
    
#Documents Serializer
class DocumentsSerializer(serializers.ModelSerializer):
    class Meta:
        model = DocumentsModel
        fields = ['passport', 'visa', 'embassy_letter', 'contract_paper', 'driving_license']


    def create(self, validated_data):
        user = self.context.get('user')
        documents = DocumentsModel.objects.create(user=user, **validated_data)
        return documents
    

class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ['pidx', 'total_amount', 'purchase_order_id', 'purchase_order_name', 'status', 'created_at']
    
    def create(self, validated_data):
        user = self.context.get('user')
        payment_detail = Payment.objects.create(user=user, **validated_data)
        return payment_detail

class ApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Application
        fields = ['user', 'application_status', 'description', 'date_of_submission']
        extra_kwargs = {'application_status': {'default': 'Unsubmit'}}
    
    def create(self, validated_data):
        user = self.context.get('user')
        appInfo = Application.objects.create(user=user, **validated_data)
        return appInfo
    
