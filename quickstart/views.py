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