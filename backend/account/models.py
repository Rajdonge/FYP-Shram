from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser


class UserManager(BaseUserManager):
    def create_user(self, email, name,  date_of_birth, gender, address, contact, password=None, password2=None):
        """
        Creates and saves a User with the given email, name,  date_of_birth, gender, address, contact, password=None, password2=None.
        """
        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(
            email=self.normalize_email(email),
            name=name,
            date_of_birth=date_of_birth,
            gender=gender,
            address=address,
            contact=contact
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, date_of_birth, gender, address, contact, password=None):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            email,
            name,
            date_of_birth=date_of_birth,
            gender=gender,
            address=address,
            contact=contact,
            password=password,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    GENDER_CHOICES = [
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other'),
    ]
    email = models.EmailField(
        verbose_name="email address",
        max_length=255,
        unique=True,
    )
    name = models.CharField(max_length=255)
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    address = models.CharField(max_length=255)
    contact = models.CharField(max_length=10)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "date_of_birth", "gender", "address", "contact"]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin
    
      
class FamilyDetailModel(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='Family_Information')
    father_name = models.CharField(max_length=255)
    mother_name = models.CharField(max_length=255)
    mobile_number = models.CharField(max_length=20)

    def __str__(self):
        return f"Family information for {self.user.email}"
