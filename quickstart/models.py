from __future__ import unicode_literals

from django.db import models
from datetime import datetime
#from django.contrib.auth.models import User

# Create your models here.
class AppUser(models.Model):
	updated = models.DateTimeField(auto_now_add = True)
	name = models.CharField(max_length = 100, blank = False, default = 'Name')
	email = models.EmailField()
	phone = models.BigIntegerField()
	owner = models.ForeignKey('auth.User', related_name = 'app_user', default = 'Name')
	#user = models.OneToOneField(User, on_delete=models.CASCADE, default = 'Name')

	class Meta:
		ordering = ('updated',)
		app_label = 'quickstart'


