import logging
from django import forms
from django.core.exceptions import ValidationError


logger = logging.getLogger(__name__)

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField()
    otp = forms.CharField()

    def clean(self):
        cleaned_data = super().clean()
        logger.info('LoginForm cleaned data: %s', cleaned_data)
        username = cleaned_data.get("username")
        password = cleaned_data.get("password")
        otp = cleaned_data.get("otp")
        
        # Perform your validation here, if any, and raise ValidationError if needed
        # For example:
        if not username or not password or not otp:
            raise ValidationError('All fields are required')