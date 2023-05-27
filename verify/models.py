from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

# Create your models here.

#This class defines all the methods required to create a user - inherits from BaseUserManager
class UserAccountManager(BaseUserManager):
    
    # create_superuser method, creates the admin/superuser
    def create_superuser(self, username,email, phone_number,password,**other_fields):
        other_fields.setdefault('is_staff', True)
        other_fields.setdefault('is_superuser', True)
        other_fields.setdefault('is_active', True)
      
        if other_fields.get('is_staff') is not True:
            raise ValueError('Superuser must be assigned to is_staff=True')
       
        if other_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must be assigned to is_superuser=True')
        user =  self.create_user(username,email, phone_number, password, **other_fields)
        user.set_password(password)
        user.save()
        return user
    
    #  create_user method - creates regular users
    
    def create_user(self, username, email=None, phone_number=None, password=None, **other_fields):
        email = self.normalize_email(email) if email else None

        user = self.model(username=username, email=email, phone_number=phone_number, **other_fields)
        user.set_password(password)
        user.save()
        return user


# User class which inherits from AbstractBaseUser and PermissionsMixin.
class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=20)
    last_otp = models.IntegerField(null=True)
    otp_expiry = models.DateTimeField(null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    def __str__(self):
        return self.email