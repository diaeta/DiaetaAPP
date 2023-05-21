# views.py

from django.contrib.auth import authenticate, login
from django.core.cache import cache
from django.core.exceptions import SuspiciousOperation
from django.shortcuts import render, redirect
from .forms import LoginForm

def login_view(request):
    ip = request.META['REMOTE_ADDR']  # Get client IP address
    attempts = cache.get(ip, 0)  # Get the number of failed attempts from cache

    if attempts > 5:  # Block after 5 failed attempts
        raise SuspiciousOperation("Too many failed login attempts")

    if request.method == 'POST':
        form = LoginForm(request.POST)

        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            otp = form.cleaned_data.get('otp')
            user = authenticate(request, username=username, password=password)

            if user is not None:
                if user.verify_otp(otp):
                    login(request, user)
                    return redirect('dashboard')
                else:
                    form.add_error('otp', 'Invalid one-time password')
                    cache.set(ip, attempts + 1, 300)  # Increment attempts and set 5 minute expiration
            else:
                form.add_error(None, 'Invalid username or password')
                cache.set(ip, attempts + 1, 300)

    else:
        form = LoginForm()

    return render(request, 'login.html', {'form': form})
