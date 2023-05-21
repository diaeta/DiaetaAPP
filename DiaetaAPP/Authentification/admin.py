from django.contrib import admin
from django.utils.html import format_html
from .models import User

class UserAdmin(admin.ModelAdmin):
    readonly_fields = ('otp_qr_code_image',)

    def otp_qr_code_image(self, obj):
        return format_html(obj.otp_qr_code())
    otp_qr_code_image.short_description = 'OTP QR Code'

admin.site.register(User, UserAdmin)
