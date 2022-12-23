from django.contrib import admin
from .models import Question, Choice, Application_User, Application_User_Credentials, Application_User_Messages

# Register your models here.

admin.site.register(Question);
admin.site.register(Choice);
admin.site.register(Application_User);
admin.site.register(Application_User_Credentials);
admin.site.register(Application_User_Messages);
