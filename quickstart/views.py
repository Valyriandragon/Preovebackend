from django.shortcuts import render

# Create your views here.
from django.contrib.auth.models import User
from quickstart.models import AppUser
from quickstart.serializers import AppUserSerializer, UserSerializer, SignUpSerializer, SocialSignUpSerializer
from rest_framework import mixins
from rest_framework import generics
from quickstart.permissions import IsAuthenticatedOrCreate
from rest_framework.views import APIView
from . import authentication, serializers 
from django.shortcuts import render_to_response, redirect
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.template.context import RequestContext
from django.http import HttpResponse


from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.response import Response
from social.apps.django_app.utils import load_strategy
from social.apps.django_app.utils import load_backend
from social.backends.oauth import BaseOAuth1, BaseOAuth2
from social.exceptions import AuthAlreadyAssociated




class SignUp(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignUpSerializer
    permission_classes = (IsAuthenticatedOrCreate,)

User = get_user_model()


class SocialSignUp(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SocialSignUpSerializer
    
    permission_classes = (IsAuthenticatedOrCreate,)

    def create(self, request, *args, **kwargs):
        """
        Override `create` instead of `perform_create` to access request
        request is necessary for `load_strategy`
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        provider = request.data['provider']

        # If this request was made with an authenticated user, try to associate this social 
        # account with it
        authed_user = request.user if not request.user.is_anonymous() else None

        # `strategy` is a python-social-auth concept referencing the Python framework to
        # be used (Django, Flask, etc.). By passing `request` to `load_strategy`, PSA 
        # knows to use the Django strategy
        strategy = load_strategy(request)
        # Now we get the backend that corresponds to our user's social auth provider
        # e.g., Facebook, Twitter, etc.
        backend = load_backend(strategy=strategy, name=provider, redirect_uri=None)

        if isinstance(backend, BaseOAuth1):
            # Twitter, for example, uses OAuth1 and requires that you also pass
            # an `oauth_token_secret` with your authentication request
            token = {
                'oauth_token': request.data['access_token'],
                'oauth_token_secret': request.data['access_token_secret'],
            }
        elif isinstance(backend, BaseOAuth2):
            # We're using oauth's implicit grant type (usually used for web and mobile 
            # applications), so all we have to pass here is an access_token
            token = request.data['access_token']

        try:
            # if `authed_user` is None, python-social-auth will make a new user,
            # else this social account will be associated with the user you pass in
            user = backend.do_auth(token, user=authed_user)
        except AuthAlreadyAssociated:
            # You can't associate a social account with more than user
            return Response({"errors": "That social media account is already in use"},
                            status=status.HTTP_400_BAD_REQUEST)

        if user and user.is_active:
            # if the access token was set to an empty string, then save the access token 
            # from the request
            auth_created = user.social_auth.get(provider=provider)
            if not auth_created.extra_data['access_token']:
                # Facebook for example will return the access_token in its response to you. 
                # This access_token is then saved for your future use. 
               
               
                auth_created.extra_data['access_token'] = token
                auth_created.save()

            # Set instance since we are not calling `serializer.save()`
            serializer.instance = user
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, 
                            headers=headers)
        else:
            return Response({"errors": "Error with social authentication"},
                            status=status.HTTP_400_BAD_REQUEST)





class AppUserList(generics.ListCreateAPIView):
	queryset = AppUser.objects.all()
	serializer_class = AppUserSerializer

	def perform_create(self,serializer):
		if self.request.user.is_anonymous():
			
			user = User.objects.create_user(username=self.request.data['name'])
			user.app_user = self.request.data
		else:
			serializer.save(owner = self.request.user)


class AppUserDetails(generics.RetrieveUpdateDestroyAPIView):
	queryset = AppUser.objects.all()
	serializer_class = AppUserSerializer


class UserList(generics.ListCreateAPIView):
	queryset = User.objects.all()
	serializer_class = UserSerializer


class UserDetails(generics.RetrieveUpdateDestroyAPIView):
	queryset = User.objects.all()
	serializer_class = UserSerializer


class AuthView(APIView):
    authentication_classes = (authentication.QuietBasicAuthentication,)
    serializer_class = serializers.UserSerializer
 
    def post(self, request, *args, **kwargs):
        return Response(self.serializer_class(request.user).data)







# @api_view(['GET', 'PUT', 'DELETE'])
# def AppUser_detail(request, pk):
# 	try:
# 		appuser = AppUser.objects.get(pk=pk)
# 	except AppUser.DoesNotExist:
# 		return Response(status=status.HTTP_404_NOT_FOUND)

# 	if request.method == 'GET':
# 		serializer = AppUserSerializer(appuser)
# 		return Response(serializer.data)

# 	elif request.method == 'PUT':
# 		serializer = AppUserSerializer(appuser, data=request.data)
# 		if serializer.is_valid():
# 			serializer.save()
# 			return Response(serializer.data)
# 		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# 	elif request.method == 'DELETE':
# 		snippet.delete()
# 		return HttpResponse(status=status.HTTP_204_NO_CONTENT)



# class AppUserList(mixins.ListModelMixin,
# 	mixins.CreateModelMixin,
# 	generics.GenericAPIView):
# 	queryset = AppUser.objects.all()
# 	serializer_class = AppUserSerializer

# 	def get(self,request, *args, **kwargs):
# 		return self.list(request, *args, **kwargs)

# 	def post(self,request, *args, **kwargs):
# 		return self.create(request, *args, **kwargs)


# class AppUserDetails(mixins.RetrieveModelMixin,
# 	mixins.UpdateModelMixin,
# 	mixins.DestroyModelMixin,
# 	generics.GenericAPIView):
# 	queryset = AppUser.objects.all()
# 	serializer_class = AppUserSerializer

# 	def get(self,request,*args,**kwargs):
# 		return self.retrieve(request,*args,**kwargs)

# 	def put(self,request,*args,**kwargs):
# 		return self.update(request,*args,**kwargs)

# 	def delete(self,request,*args,**kwargs):
# 		return self.destroy(request,*args,**kwargs)

#starting of otp computing and verifiaction 

#!/usr/bin/env python
#
# Copyright 2011 Viewfinder Inc. All Rights Reserved.

"""Creates and verifies one time passwords (OTPs).

OTPs are implemented as an SHA1 digest of:
  - user secret
  - GMT (UTC) time rounded to nearest 30s increment

This module tracks the number of OTP attempts and the specific codes
encountered so it can warn of brute-force or MITM attacks.

The OTP tokens generated are compatible with Google Authenticator,
and the mobile devices it supports.

Example Usage:

For a new administrator, run the following to create a secret for the
admin and get a verification code and QRcode URL for initializing
Google Authenticator:

% python -m viewfinder.backend.base.otp --otp_mode=new_secret --domain=viewfinder.co --user=<user>

To set a password for the admin:

% python -m viewfinder.backend.base.otp --otp_mode=set_pwd --user=<user>

To display an existing secret, as well as the verification code and
QRcode URL:

% python -m viewfinder.backend.base.otp --otp_mode=display_secret --user=<user>


To get an OTP value for a user:

% python -m viewfinder.backend.base.otp --otp_mode=get --user=<user>

To verify an OTP:

% python -m viewfinder.backend.base.otp --otp_mode=verify --user=<user> --otp=<otp>

To generate random bytes:

% python -m viewfinder.backend.base.otp --otp_mode=(random,randomb64) --bytes=<bytes>


  OTPException: exception for otp verification errors.

  GetOTP(): returns the otp for the requesting user at current time.
  VerifyOTP(): verifies an OTP for requesting user.
  CreateUserSecret(): creates and persists a user's secret.
  CreateRandomBytes(): creates random bytes.
  GetPassword(): returns the encrypted user password.
  SetPassword(): sets a user password from stdin.
  VerifyPassword(): verifies a user password.

  GetAdminOpener(): returns an OpenerDirector for retrieving administrative URLs.
"""


import base64
import bisect
import http.cookiejar
import getpass
import hashlib
import hmac
import json
import logging
import os
import re
import struct
import sys
import time
try:
    import urllib.request as urllib2
except ImportError:
    import urllib2
import http.client
http.client.HTTPConnection._http_vsn = 10
http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'

from Crypto.Protocol.KDF import PBKDF2
from os.path import expanduser
from tornado import ioloop, options
#from viewfinder.backend.base import base_options

#import secrets, util


options.define("otp_mode", "get",help="one of { get, verify, new_secret, set_pwd }")
options.define("otp", None, help="the otp if otp_mode=verify was set")
options.define("user", "tapan", help="username")
options.define("bytes", 128, help="number of bytes to generate")

_SECRET_BYTES = 10
_GRANULARITY = 30
_TIMEOUT = 180
_VERIFY_MODULUS = 1000 * 1000
_ATTEMPTS_PER_MIN = 3

_PASSWORD_VERSION_MD5 = 0  # md5 with a global "salt"
_PASSWORD_VERSION_PBKDF2 = 1  # pbkdf2 with 10k iterations of sha1

_CURRENT_PASSWORD_VERSION = _PASSWORD_VERSION_PBKDF2


# History keeps track of the timestamps of recent login attempts,
# as well as all provided OTP codes.
_history = {}


class OTPException(Exception):
  """Subclass of exception to communicate error conditions upon
  attempted verification of OTP. In particular, too many unsuccesful
  OTP entry attempts or repeated tokens.
  """
  pass

def decode_base64(data):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += b'='* missing_padding
    return base64.decodestring(data)


def _ComputeOTP(secret,t):
  """Computes the HMAC hash of the user secret, and time (in 30s of
  seconds from the epoch). SHA1 is used as the internal digest and
  time is packed in big-endian order into an 8 byte string. Four
  bytes are 2tracted from the resulting digest (20 bytes in length
  for SHA1) based on an offset computed from the last byte of the
  digest % 0xF (e.g. from 0 to 14). The result is adjusted for
  negative values and taken modulo _VERIFY_MODULUS to yield a
  positive, N-digit OTP, where N = log10(_VERIFY_MODULUS).
  """
  h = hmac.new(decode_base64(secret), struct.pack('>Q', t), hashlib.sha1)
  hash = h.digest()
  offset = struct.unpack('B', hash[0:1])[0] & 0xF
  truncated_hash = struct.unpack('>I', hash[offset:offset + 4])[0]
  truncated_hash &= 0x7FFFFFFF
  truncated_hash %= _VERIFY_MODULUS
  #truncated_hash = '007'
  return truncated_hash
  


def _SecretName(user):
  """Returns the name of the secret file for the specified user.
  """
  return "{0}_otp".format(user)


def _PasswordName(user):
  """Returns the name of the password file for the specified user.
  """
  return "{0}_pwd".format(user)


def _GenerateSalt(version):
  if version == _PASSWORD_VERSION_MD5:
    return ""
  elif version == _PASSWORD_VERSION_PBKDF2:
    return base64.b64encode(os.urandom(8))
  raise ValueError("unsupported password version")


def _HashPassword(password, version, salt):
  """Hashes the provided password according to the specified version's policy.

  The result is base32 encoded.
  """
  if version == _PASSWORD_VERSION_MD5:
    m = hashlib.md5()
    m.update(password)
    m.update(secrets.GetSecret("cookie_secret"))
    hashed = m.digest()
  elif version == _PASSWORD_VERSION_PBKDF2:
    hashed = PBKDF2(password, base64.b64decode(salt), count=10000)
  return base64.b32encode(hashed)


def _GetUserSecret():
  """Returns the user secret by consulting the secrets database."""
  secret = b'0007'
  return secret



def GetOTP(user):
  """Gets a new OTP for the specified user by looking up the
  user's secret in the secrets database and using it to salt an
  MD5 hash of time and username.
  """
  return _ComputeOTP(_GetUserSecret(), int(time.time()/ _GRANULARITY) )

def _GetActivationURL(user):
  """Generates a URL that displays a QR code on the browser for activating
  mobile devices with user secret.
  """
  return urllib2.urlopen("http://enterprise.smsgupshup.com/GatewayAPI/rest?method=SendMessage&send_to=7023297788&msg={0}Working%20{1}!&msg_type=TEXT&userid=2000159892&auth_scheme=plain&password=xmtThebYV&v=1.1&format=text".format(user,GetOTP(user)))
  #return urllib2.urlopen('http://127.0.0.1:8000/users')
  
def VerifyOTP(user, otp):
  """Verifies the provided OTP for the user by comparing it to one
  generated right now, with successive checks both going forward and
  backwards in time to cover timeout range. This accounts for clock
  skew or delay in entering the OTP after fetching it.
  """
  timestamp = int(time.time())
  challenge = timestamp / _GRANULARITY
  units = _TIMEOUT / _GRANULARITY

  secret = _GetUserSecret(user)
  ts = _UpdateUserHistory(user, timestamp, otp)
  if len(ts) - bisect.bisect_left(ts, (timestamp - 60,)) > _ATTEMPTS_PER_MIN:
    raise OTPException("Too many OTP login attempts for {0} "
                       "in past minute".format(user))
  if  [True for x in ts[:-1] if x[1] == otp]:
    raise OTPException("Have already seen OTP {0} for "
                       "{1}".format(otp, user))

  for offset in range(-(units - 1) / 2, units / 2 + 1):
    if int(otp) == _ComputeOTP(secret, challenge + offset):
      return
  raise OTPException("Entered OTP invalid")





       



 