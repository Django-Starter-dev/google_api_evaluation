from django.urls import path
from . import views

urlpatterns = [
    path('signup',views.signup, name='Signup_Template'),
    path('login',views.login, name='Login_Template'),
    path('home',views.home, name='Home_Template'),
    path('fetch_emails',views.fetch_emails, name='fetch_emails'),
    path('validate',views.validate, name='validate'),
    path('validateauthcode',views.validateauthcode, name='Validateauthcode_Endpoint'),
    path('jsonresponse/usermessages', views.user_emails, name='userMessages'),
    path('jsonresponse/paginatedusermessages', views.paginated_user_emails, name='paginatedUserMessages'),
]