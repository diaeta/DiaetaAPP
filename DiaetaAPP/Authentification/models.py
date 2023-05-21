from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.html import mark_safe
from .utils import get_fernet
import pyotp
from segno import helpers

class User(AbstractUser):
    otp_secret_encrypted = models.BinaryField(null=True)

    # Decrypts OTP secret on the fly when otp_secret is accessed
    @property
    def otp_secret(self):
        return get_fernet().decrypt(self.otp_secret_encrypted).decode() if self.otp_secret_encrypted else None

    # Encrypts OTP secret on the fly when otp_secret is set
    @otp_secret.setter
    def otp_secret(self, value):
        self.otp_secret_encrypted = get_fernet().encrypt(value.encode())

    # Call this method when you want to generate a new secret
    def generate_new_otp_secret(self):
        self.otp_secret = pyotp.random_base32()

    def otp_qr_code(self):
        try:
            if not self.otp_secret:
                return 'No OTP Secret generated yet.'
            otp_auth_url = pyotp.totp.TOTP(self.otp_secret).provisioning_uri(name=self.email, issuer_name="DiaetaApp")
            qr_code = helpers.make(otp_auth_url)
            return mark_safe('<img src="{}">'.format(qr_code.get_image().to_data_url()))
        except Exception as e:
            return str(e)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.otp_secret_encrypted:  # if otp_secret is not set
            self.generate_new_otp_secret()
