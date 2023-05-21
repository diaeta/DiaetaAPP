# forms.py

from django import forms
from django.contrib.auth.forms import AuthenticationForm

# This form is used in the login view
class LoginForm(AuthenticationForm):
    otp = forms.CharField(max_length=6, required=True)
