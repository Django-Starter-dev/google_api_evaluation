from django.urls import path
from . import views

urlpatterns = [
    path('signup',views.signup, name='Signup_Template'),
    path('login',views.login, name='Login_Template'),
    path('home',views.home, name='Home_Template'),
    path('validate',views.validate, name='validate'),
    path('validateauthcode',views.validateauthcode, name='Validateauthcode_Endpoint')
]