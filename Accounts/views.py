from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib import auth
from django.contrib.auth import authenticate, login as auth_login, logout
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from jb1 import settings

# USER REGISTRATION


def register(request):
    if request.method == 'POST':
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username = request.POST['username']
        email = request.POST['email']
        password1 = request.POST['password1']
        password2 = request.POST['password2']

        user = User.objects.create_user(
            first_name=first_name,
            last_name=last_name,
            username=username,
            email=email,
            password=password1
        )
        user.is_active = True #SET TO FALSE : so that  if the email address is not activated the user will not be able to log in to their account
        user.save()
        send_verification_email(request, user)
        messages.info(request, 'Account created. Please check your email to confirm your account.')
        return redirect('signin')
        
        if password1 != password2:
            messages.error(request, 'Passwords do not match.')
            return redirect('register')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username is taken.')
            return redirect('register')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email is already in use.')
            return redirect('register')

    else:
        return render(request, 'register.html')

      
# USER LOGIN 


def signin(request):
    if request.method == 'POST':
        username = request.POST.get('username').strip()  
        password = request.POST.get('password').strip()

        user = authenticate(username=username, password=password)
        if user is not None:
            auth_login(request, user)
            return redirect('home')  
        else:
            messages.error(request, 'Invalid credentials. Please try again.')
            return redirect('signin')
    else:
        return render(request, 'signin.html')




# USER LOGOUT

def signout(request):
    auth.logout(request)
    return redirect('/')

# EMAIL VERIFICATION


def send_verification_email(request, user):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    current_site = get_current_site(request)
    subject = 'Activate Your Account'
    message = render_to_string('email_verification.html', {
        'user': user,
        'domain': current_site.domain,
        'uid': uid,
        'token': token,
    })
    recipient_email = user.email 
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [recipient_email])
    

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = False
        user.save()
        auth_login(request, user)
        return redirect('home')
    else:
        messages.error(request, 'Activation link is invalid!')
        return redirect('signin')


def home(request):
    return render(request, 'index.html')