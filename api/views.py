from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTTokenUserAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import (
    JWTStatelessUserAuthentication
)
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from .serializers import (
    RegisterUserSerializer,
    LoginUserSerializer,
    VerifyOTPSerializer,
    EditProfileSerializer
)
from rest_framework_simplejwt.token_blacklist.models import (
    OutstandingToken,
    BlacklistedToken
)
from .send_mail import send_otp
from .models import User
import random


class RegisterUserViews(APIView):
    def post(self, request):
        serializer = RegisterUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.validated_data['password'] = make_password(
                serializer.validated_data["password"])
            serializer.save()
            return Response(
                {
                    "message": "Successfully registered user"
                },
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {
                    "message": "Registration Failed",
                    "data": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )


class LoginUser(APIView):
    #    permission_classes = (IsAuthenticated, )

    def post(self, request):
        serializer = LoginUserSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(username=serializer.data["username"],
                                password=serializer.data["password"]
                                )
            if user is not None:
                refresh = RefreshToken.for_user(user)
                data = {"access_token": str(refresh.access_token), "refresh_token": str(refresh)}
                message = f"sent otp to {user.email} mail successfully"
                random_number = random.randint(100000, 999999)
            
                send_otp(user.email, random_number)

                if user.login_otp is not None:
                    user.login_otp = ""
                user.login_otp = random_number
                user.save()
                return Response(
                    {
                        "message": message,
                        "data": data
                    },

                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {
                        "message": "Invalid username or password"
                    },
                    status=status.HTTP_200_OK
                )
        else:
            return Response(
                {
                    "message": "Incorrect username or password were provided",
                    "data": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )


class VerifyOTP(APIView):
    # authentication_classes = (TokenAuthentication, )
    permission_classes = (IsAuthenticated, )

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            try:
                auth_token = JWTTokenUserAuthentication.get_header(
                    self, request)
                jwt_token = auth_token.split()[1]
                access_token = AccessToken(jwt_token)
                user_id = access_token["user_id"]
                user = User.objects.get(id=user_id)
                otp_payload = serializer.data["login_otp"]
                user_otp = user.login_otp
                if user_otp == otp_payload:
                    return Response(
                        {
                            "message": "Login Verified"
                        },
                        status=status.HTTP_200_OK
                    )
                else:
                    return Response(
                        {
                            "message": "Invalid OTP"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
            except TokenError:
                return Response(
                    {
                        "message": "Invalid or Expired Token"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            return Response(
                {
                    "message": serializer.errors
                }
            )


class ProfileDetails(APIView):
    authentication_classes = (JWTStatelessUserAuthentication, )
    permission_classes = (IsAuthenticated, )

    def get(self, request):
        try:
            user_id = request.user.id
            user = User.objects.get(id=user_id)
            data = {
                "user": user.user,
                "username": user.username,
                "email": user.email
            }
            return Response(
                {
                    "message": "Successfully Retrieved Profile Details",
                    "data": data
                },
                status=status.HTTP_200_OK
            )
        except User.DoesNotExist:
            return Response(
                {
                    "message": "Invalid token or expired token"
                },
                status=status.HTTP_400_BAD_REQUEST
            )


class SearchUsers(APIView):
    authentication_classes = (JWTStatelessUserAuthentication, )
    permission_classes = (IsAuthenticated, )

    def get(self, request):
        user_param = self.request.query_params.get("user")
        if user_param is not None:
            user_set = User.objects.filter(user__startswith=user_param)
            if user_set.exists():
                user_keys = ["user", "username", "email"]
                user_list = []
                for user in user_set:
                    user_list.append([user.user, user.username, user.email])
                print(user_list)
                users = [dict(zip(user_keys, user)) for user in user_list]

                return Response(
                    {
                        "message": "Successfully Retrieved Data",
                        "data": users
                    },
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {
                        "message": "No users found"
                    },
                    status=status.HTTP_200_OK
                )
        else:
            user_id = request.user.id
            try:
                user = User.objects.get(id=user_id)
                data = {
                    "user": user.user,
                    "username": user.username,
                    "email": user.email
                }
                return Response(
                    {
                        "message": "Successfully Retrieved Profile Details",
                        "data": data
                    },
                    status=status.HTTP_200_OK
                )
            except User.DoesNotExist:
                return Response(
                    {
                        "message": "User does not exist"
                    }
                )


class EditProfile(APIView):
    authentication_classes = (JWTStatelessUserAuthentication, )
    permission_classes = (IsAuthenticated, )

    def put(self, request):
        serializer = EditProfileSerializer(data=request.data)
        if serializer.is_valid():
            user_id = request.user.id
            user = User.objects.get(id=user_id)
            user.username = serializer.validated_data["username"]
            user.save()

            return Response(
                {
                    "message": "Successfully updated details",
                },
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {
                    "data": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )


class Logout(APIView):
    authentication_classes = (JWTStatelessUserAuthentication, )
    permission_classes = (IsAuthenticated, )

    def delete(self, request):
        try:
            user_id = request.user.id
            user = User.objects.filter(id=user_id)
            print(user)
            user_token = OutstandingToken.objects.filter(user_id=user_id).first()

            token = RefreshToken(user_token.token)
            token.blacklist()
            print(user_token.token)
            return Response(
                {
                    "message": "logged out successfully"
                }
            )
        except TokenError:
            return Response(
                {
                    "message": "Token expired or logged out successfully"
                }
            )
