import re
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from .models import User

# Regex's for username, name and email
username_pattern = r"[\w.]{3,32}"
valid_username = re.compile(username_pattern)

user_pattern = r"[a-zA-Z\s]{6,64}"
valid_user = re.compile(user_pattern)

email_pattern = r"[a-zA-Z0-9_\.]+@[a-z]+.[a-z]{2,4}"
valid_email = re.compile(email_pattern)


def validate_email(email):
    """
        if an email already exists
    """
    if valid_email.match(email):
        pass
    else:
        raise serializers.ValidationError("Enter a valid email address")
    try:
        User.objects.get(email=email)
        raise serializers.ValidationError("Email Already Registered")
    except User.DoesNotExist:
        pass
    return email


def validate_user(user):
    """
        Validate User and check if the user
    """
    if valid_user.match(user):
        pass
    else:
        raise serializers.ValidationError("Invalid Name")
    return user


def validate_username(username):
    """
        Validate username and check if the user
        exists in the database
    """
    if valid_username.match(username):
        pass
    else:
        raise serializers.ValidationError(f"{username} is an invalid username")

    try:
        User.objects.get(username=username)
        raise serializers.ValidationError(f"{username} already exists")
    except User.DoesNotExist:
        pass

    return username


class RegisterUserSerializer(serializers.ModelSerializer):
    user = serializers.CharField(validators=[validate_user], max_length=64)
    username = serializers.CharField(
        validators=[validate_username], max_length=32)
    email = serializers.EmailField(validators=[validate_email])
    password = serializers.CharField(min_length=6, max_length=64)
    profile_picture = serializers.ImageField()

    class Meta:
        model = User
        fields = ["user", "username", "email", "password", "profile_picture"]


class LoginUserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=32)
    password = serializers.CharField(min_length=6, max_length=64)

    def validate_username(self, username):
        """
            Validate username
        """
        if valid_username.match(username):
            pass
        else:
            raise serializers.ValidationError("{username} is invalid")

        return username

    class Meta:
        model = User
        fields = ["username", "password"]


class VerifyOTPSerializer(serializers.ModelSerializer):
    login_otp = serializers.IntegerField(min_value=100000, max_value=999999)

    class Meta:
        model = User
        fields = ["login_otp"]


class SearchSerializer(serializers.ModelSerializer):
    user = serializers.CharField(max_length=64)

    class Meta:
        model = User
        fields = ["user"]


class EditProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(
        validators=[validate_username], max_length=64)

    class Meta:
        model = User
        fields = ["username"]
