#Import Dependencies

from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.decorators import api_view
from django.core.serializers import serialize
from django.conf import settings
from datetime import datetime, timedelta
from django.utils.timezone import now
from django.utils import timezone
from django.shortcuts import redirect
from .models import User
from django.db.models import Q
from django.core.mail import send_mail
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.core.mail import send_mail
from twilio.rest import Client
import jwt
import random
import os
from dotenv import load_dotenv

#Views begin here.

# Load environment variables from .env file
load_dotenv()
TWILIO_SID = os.getenv('TWILIO_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')

# Implement the user registration endpoint

@csrf_exempt
def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        phone_number = request.POST.get('phone_number')
        
        # Save the user in the database
        user = User.objects.create_user(username=username, email=email, phone_number=phone_number, password=None)

        # Generate OTP
        otp = random.randint(1000, 9999)
        # otp_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)  # Set OTP expiry to 5 minutes from now
        otp_expiry = datetime.now() + timedelta(minutes=5)
        # Save OTP and OTP expiry time to the user
        user.last_otp = otp
        user.otp_expiry = otp_expiry
        user.save()
       
        # Send OTP to the user's phone number
        client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=f'Your OTP is {otp}',
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
         # Generate JWT token
        payload = {
                'user_id': user.pk,
                'username': user.username,
                'email':user.email,
                'phone':user.phone_number
                
    
            }
        token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
            
        # Generate magic link URL
        current_site = get_current_site(request)
        magic_link_url = f'http://{current_site.domain}{reverse("verify_magic_link")}?token={token}'

        # Send OTP and verification URL to the user's email
        send_mail(
            subject='OTP Verification',
            message=f'Congratulations {user.email} account created successfully. Your OTP is {otp}. You can also login via this Magic_link_url: {magic_link_url}',
            from_email='mamakwizeens@gmail.com',
            recipient_list=[email],
            fail_silently=False,
        )

        return JsonResponse({'status': 'success'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'})
    


# Login user
@csrf_exempt
def login(request):
    if request.method == 'POST':
        identifier = request.POST.get('identifier')

        try:
            user = User.objects.get(Q(email=identifier) | Q(phone_number=identifier))
        except User.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User does not exist, create an account'})

        # Determine verification method based on identifier type
        if '@' in identifier:
            method = 'email'
        else:
            method = 'phone'

        # Generate OTP
        otp = random.randint(1000, 9999)

        if method == 'phone':
            # Send OTP to the user's phone number
            client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)
            message = client.messages.create(
                body=f'Your OTP is {otp}',
                from_=TWILIO_PHONE_NUMBER,
                to=user.phone_number
            )
        elif method == 'email':
            
            # Generate JWT token
            payload = {
                'user_id': user.pk,
                'username': user.username,
                'email':user.email,
                'phone':user.phone_number
                
    
            }
            token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
            
             # Generate magic link URL
            current_site = get_current_site(request)
            magic_link_url = f'http://{current_site.domain}{reverse("verify_magic_link")}?token={token}'
                
            # Send OTP and verification URL to the user's email
            send_mail(
                subject='Magic Link and OTP Verification',
                message=f'Hello {user.email} Your OTP is {otp}. Click this link to access your account: {magic_link_url}',
                from_email='mamakwizeens@gmail.com',
                recipient_list=[user.email],
                fail_silently=False,
            )
        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid login method'})
        
        # Save the OTP and its expiry timestamp in the user's record
        user.last_otp = otp
        user.otp_expiry = datetime.now() + timedelta(minutes=5)
        user.save()
        
        return JsonResponse({'status': 'Success, Check phone or email for OTP code'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'})  
    

# Action to Verify the magic Link
@api_view(['GET'])
def verify_magic_link(request):
    token = request.GET.get('token')
    if token:
        try:
            decoded_token = jwt.decode(token, settings.JWT_SECRET_KEY, settings.JWT_ALGORITHM)
            user_id = decoded_token.get('user_id')
            user = User.objects.get(id=user_id)
            
            # serialized_user = serialize('json', [user])  
            
    
            # Generate JWT access token
            access_token = jwt.encode({'user_id': user.id}, settings.JWT_SECRET_KEY, algorithm='HS256')
            
            #  access_token = jwt.encode({'user_id': user.id}, settings.JWT_SECRET_KEY, algorithm='HS256')
            # Redirect to the frontend dashboard route with the access token as a query parameter
            # frontend_dashboard_url = f'http://my-frontend.com/dashboard?token={access_token}'
            frontend_dashboard_url = f'http://localhost:3000/dashboard?token={access_token}'
            return redirect(frontend_dashboard_url)
            #return JsonResponse({'user': access_token})
        except (jwt.ExpiredSignatureError, jwt.DecodeError, User.DoesNotExist):
            return JsonResponse({'status': 'error', 'message': 'Invalid token'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Token is required'})    
    
   
"""
# OTP Verification
@csrf_exempt
def verify_otp(request):
    if request.method == 'POST':
        otp = request.POST.get('otp')

        try:
            user = User.objects.get(last_otp=otp)
        except User.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Invalid OTP'})

        # Check if the OTP has expired
        if user.otp_expiry and user.otp_expiry < timezone.now():
            return JsonResponse({'status': 'error', 'message': 'OTP has expired'})

        # OTP verification successful
        # Generate JWT
        payload = {
            'username': user.username,
            'phone_number': user.phone_number,
            'email': user.email,
            'last_otp': user.last_otp  # Add last_otp field
        }
        jwt_token = jwt.encode(payload, JWT_SECRET_KEY)

        return JsonResponse({'status': 'success', 'jwt_token': jwt_token})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'})
    
           """



@csrf_exempt
def verify_otp(request):
    if request.method == 'POST':
        otp = request.POST.get('otp')
        # user = User.objects.get(last_otp=otp)
        
        # serialized_user = serialize('json', [user])
     
        # return JsonResponse({'user': serialized_user})
        

        try:
            user = User.objects.get(last_otp=otp)
        except User.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Invalid OTP'})

        # Check if the OTP has expired
        if user.otp_expiry and user.otp_expiry < timezone.now():
            return JsonResponse({'status': 'error', 'message': 'OTP has expired'})

        # Check if the provided OTP matches the last OTP stored in the user model
        # if otp != user.last_otp:
        #     return JsonResponse({'status': 'error', 'message': 'Invalid OTP'})

        # OTP verification successful
        # Generate JWT
        payload = {
            'username': user.username,
            'phone_number': user.phone_number,
            'email': user.email,
            'last_otp': user.last_otp  # Add last_otp field
        }
        jwt_token = jwt.encode(payload, JWT_SECRET_KEY)

        return JsonResponse({'status': 'success', 'jwt_token': jwt_token})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'})
           