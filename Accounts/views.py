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

        # Check if passwords match
        if password1 != password2:
            messages.error(request, 'Passwords do not match.')
            return redirect('register')

        # Check if username is already taken
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username is taken.')
            return redirect('register')

        # Check if email is already in use
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email is already in use.')
            return redirect('register')

        # Create the user if no issues
        user = User.objects.create_user(
            first_name=first_name,
            last_name=last_name,
            username=username,
            email=email,
            password=password1
        )
        user.is_active = True  # Set to False until email is verified
        user.save()

        # Send email verification
        send_verification_email(request, user)

        # Display success message
        messages.success(request, f'Hello {user.first_name} {user.last_name}, your account has been created. Please check your email to verify your account.')
        return redirect('signin')
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

# def signout(request):
#     auth.logout(request)
#     return redirect('/')

def signout(request):
    logout(request)
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
        user.is_active = True  # Activate the user's account
        user.save()
        auth_login(request, user)
        messages.success(request, 'Your account has been activated successfully!')
        return redirect('home')
    else:
        messages.error(request, 'Activation link is invalid!')
        return redirect('signin')




    



