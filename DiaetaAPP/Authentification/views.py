# views.py

import logging
from django.contrib.auth import authenticate, login
from django.core.cache import cache
from django.core.exceptions import SuspiciousOperation
from django.shortcuts import render, redirect
from django.views import View
from .forms import LoginForm
from django.core.exceptions import ObjectDoesNotExist
from .models import User

logger = logging.getLogger(__name__)

class LoginView(View):
    template_name = 'Authentification/login.html'
    form_class = LoginForm

    def get(self, request, *args, **kwargs):
        form = self.form_class()
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        logger.info("POST request received for login. Data: %s", request.POST)
        ip = request.META['REMOTE_ADDR']
        attempts = cache.get(ip, 0)

        if attempts > 5:  
            logger.warning('Too many failed login attempts from IP: %s', ip)
            raise SuspiciousOperation("Too many failed login attempts")

        form = self.form_class(request.POST)

        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            otp = form.cleaned_data.get('otp')
            try:
                user = User.objects.get(username=username) 
                if user is not None:
                    if user.verify_otp(otp):
                        user = authenticate(request, username=username, password=password)
                        if user is not None:
                            login(request, user)
                            logger.info('User logged in successfully. Redirecting to home.')
                            return redirect('dashboard:home')
                        else:
                            form.add_error(None, 'Invalid username or password')
                            cache.set(ip, attempts + 1, 300)
                            logger.error('User authentication failed.')
                    else:
                        form.add_error('otp', 'Invalid one-time password')
                        cache.set(ip, attempts + 1, 300)
                        logger.error('OTP verification failed.')
                else:
                    form.add_error(None, 'Invalid username or password')
                    cache.set(ip, attempts + 1, 300)
                    logger.error('User object not found.')
            except ObjectDoesNotExist:
                form.add_error(None, 'Invalid username or password')
                cache.set(ip, attempts + 1, 300)
                logger.error('User does not exist.')
        else:
            logger.error('Form errors: %s', form.errors.as_json())

        return render(request, self.template_name, {'form': form})
