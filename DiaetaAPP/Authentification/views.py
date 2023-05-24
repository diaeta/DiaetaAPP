# views.py

import logging
from django.contrib.auth import authenticate, login
from django.core.cache import cache
from django.core.exceptions import SuspiciousOperation
from django.shortcuts import render, redirect
from django.views import View
from .forms import LoginForm
import logging

logger = logging.getLogger(__name__)

class LoginView(View):
    print("Login view called")
    template_name = 'Authentification/login.html'
    form_class = LoginForm

    def get(self, request, *args, **kwargs):
        form = self.form_class()
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        ip = request.META['REMOTE_ADDR']  # Get client IP address
        attempts = cache.get(ip, 0)  # Get the number of failed attempts from cache
        print('IP:', ip, 'Attempts:', attempts)

        if attempts > 5:  # Block after 5 failed attempts
            logger.warning('Too many failed login attempts from IP: %s', ip)
            raise SuspiciousOperation("Too many failed login attempts")
        
        form = self.form_class(request.POST)

        if form.is_valid():
            print('Form is valid')
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            otp = form.cleaned_data.get('otp')
            print('Username:', username, 'Password:', password, 'OTP:', otp)
            try:
                user = authenticate(request, username=username, password=password)
                print("User:", user)
            except Exception as e:
                print("Error during authentication:", str(e))
                logger.error('Error during authentication: %s', str(e))
                form.add_error(None, 'Invalid username or password')
                cache.set(ip, attempts + 1, 300)
            else:
                print('User:', user)
                if user is not None:
                    print("User is not None")
                    if user.verify_otp(otp):
                        print('OTP is valid')
                        login(request, user)
                        print('Redirecting to dashboard:home')
                        return redirect('dashboard:home')
                    else:
                        print('Invalid OTP')
                        form.add_error('otp', 'Invalid one-time password')
                        cache.set(ip, attempts + 1, 300)  # Increment attempts and set 5 minute expiration
                else:
                    print('Invalid username or password')
                    form.add_error(None, 'Invalid username or password')
                    cache.set(ip, attempts + 1, 300)
                    
        else:
            print('Form errors:', form.errors.as_json())

        return render(request, self.template_name, {'form': form})
    
   
