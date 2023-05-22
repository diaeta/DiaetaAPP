# forms.py

from django import forms
from django.contrib.auth.forms import AuthenticationForm

# This form is used in the login view
class LoginForm(AuthenticationForm):
    otp = forms.CharField(
        max_length=6,
        required=True,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'OTP Code', 'aria-label': 'OTP Code', 'aria-describedby': 'basic-addon2'}), 
        label='',
    )
    username = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username', 'aria-label': 'Username', 'aria-describedby': 'basic-addon1'}), 
        label='',
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password', 'aria-label': 'Password'}), 
        label='',
    )
