from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    user = models.CharField(max_length=64)
    username = models.CharField(unique=True, max_length=32)
    email = models.EmailField()
    password = models.CharField(max_length=64)
    profile_picture = models.ImageField(blank=True, upload_to='profiles')
    login_otp = models.IntegerField(null=True)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return f'<User {self.user}, {self.username}, {self.email}>'
