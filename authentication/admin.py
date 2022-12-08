from django.contrib import admin
from .models import Question, Choice, Application_User, Application_User_Credentials

# Register your models here.

admin.site.register(Question)
admin.site.register(Choice)
admin.site.register(Application_User)
admin.site.register(Application_User_Credentials)
