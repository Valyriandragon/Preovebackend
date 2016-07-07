from django.contrib.auth.models import User, Group
from rest_framework import serializers
from quickstart.models import AppUser
from datetime import datetime

class UserSerializer(serializers.ModelSerializer):
	#appuser = serializers.PrimaryKeyRelatedField(many = True, queryset = AppUser.objects.all())

	class Meta:
		model = User
		fields = ('id', 'username','password')

class GroupSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields = ('url', 'name')


class AppUserSerializer(serializers.ModelSerializer):
	owner = serializers.ReadOnlyField(source = 'owner.id')
	class Meta:
		model = AppUser
		fields = ('owner','name','email','phone','updated')


class SignUpSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'password',)
        write_only_fields = ('password',)


class SocialSignUpSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'password')
        write_only_fields = ('password',)
