# Generated by Django 4.2.1 on 2023-05-21 20:50

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("Authentification", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="user",
            name="otp_secret_encrypted",
            field=models.BinaryField(null=True),
        ),
    ]
