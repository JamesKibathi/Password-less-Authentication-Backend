#Import Dependencies


from django.contrib.auth.models import User
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from rest_framework.decorators import api_view


from django.conf import settings



from datetime import datetime, timedelta
from tokenize import generate_tokens
from django.utils.timezone import now
from django.utils import timezone
from django.shortcuts import render
from .models import User
from django.db.models import Q
from django.core.mail import send_mail
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.core.mail import send_mail
from twilio.rest import Client
import jwt
import random
import os
from dotenv import load_dotenv

# Create your views here.

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
        # Generate magic link URL
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(str(user.pk)))
        current_site = get_current_site(request)
        magic_link_url = f'http://{current_site.domain}{reverse("verify_magic_link")}?uid={uid}&token={token}'

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
            # Generate token for magic link
            token = default_token_generator.make_token(user)
            
            # Build the magic link URL
            # current_site = get_current_site(request)
            # relative_url = reverse('verify', args=[username, token])
            # magic_link = f'http://{current_site.domain}{relative_url}'
            
             # Generate magic link URL
            uid = urlsafe_base64_encode(force_bytes(str(user.pk)))
            current_site = get_current_site(request)
            magic_link_url = f'http://{current_site.domain}{reverse("verify_magic_link")}?uid={uid}&token={token}'
                
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
            decoded_token = jwt.decode(token, settings.SECRET_KEY)
            user_id = decoded_token.get('user_id')
            user = User.objects.get(id=user_id)

            # Generate JWT access token
            access_token = AccessToken.for_user(user)

            return JsonResponse({'status': 'success', 'access_token': str(access_token)})
        except (jwt.ExpiredSignatureError, jwt.DecodeError, User.DoesNotExist):
            return JsonResponse({'status': 'error', 'message': 'Invalid token'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Token is required'})
           