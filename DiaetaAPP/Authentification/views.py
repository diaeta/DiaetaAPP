# views.py

import logging
from django.contrib.auth import authenticate, login
from django.core.cache import cache
from django.core.exceptions import SuspiciousOperation
from django.shortcuts import render, redirect

from Authentification.models import User
from .forms import LoginForm

logger = logging.getLogger(__name__)

def login_view(request):
    ip = request.META['REMOTE_ADDR']  # Get client IP address
    attempts = cache.get(ip, 0)  # Get the number of failed attempts from cache

    logger.info('User %s failed to log in %d times', ip, attempts)

    if attempts > 5:  # Block after 5 failed attempts
        raise SuspiciousOperation("Too many failed login attempts")

    if request.method == 'POST':
        form = LoginForm(request.POST)

        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            otp = form.cleaned_data.get('otp')

            try:
                user = authenticate(request, username=username, password=password)
            except User.DoesNotExist:
                form.add_error(None, 'Invalid username or password')
                cache.set(ip, attempts + 1, 300)
            else:
                if user is not None:
                    if user.verify_otp(otp):
                        login(request, user)
                        return redirect('dashboard:home')
                    else:
                        form.add_error('otp', 'Invalid one-time password')
                        cache.set(ip, attempts + 1, 300)  # Increment attempts and set 5 minute expiration
                else:
                    form.add_error(None, 'Invalid username or password')
                    cache.set(ip, attempts + 1, 300)

    else:
        form = LoginForm()

    return render(request, 'Authentification/login.html', {'form': form})