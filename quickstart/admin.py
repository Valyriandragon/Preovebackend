from django.contrib import admin

# Register your models here.
'''
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User

from quickstart.models import AppUser

# Define an inline admin descriptor for Employee model
# which acts a bit like a singleton
class AppUserInline(admin.StackedInline):
    model = AppUser
    can_delete = False
    verbose_name_plural = 'AppUser'

# Define a new User admin
class UserAdmin(BaseUserAdmin):
    inlines = (AppUserInline, )

admin.site.unregister(User)
admin.site.register(User,UserAdmin)
'''
from quickstart.models import AppUser
from quickstart.models import UserInfo

class AppUserAdmin(admin.ModelAdmin):
    list_display = ('name','email','phone',)
    list_filter = ('name',)
    class Meta:
        model = AppUser

class UserInfoAdmin(admin.ModelAdmin):
    list_display = ('phone',)
    class Meta:
        model = UserInfo



admin.site.register(AppUser, AppUserAdmin)
admin.site.register(UserInfo, UserInfoAdmin)