from django.db import models

# Create your models here.

class Question(models.Model):
    question_text = models.CharField(max_length=200)
    pub_date = models.DateTimeField('date published')


class Choice(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    choice_text = models.CharField(max_length=200)
    votes = models.IntegerField(default=0)

class Application_User(models.Model):
    id = models.CharField(max_length=100, primary_key=True)
    email = models.CharField(max_length=100)
    is_email_verified = models.BooleanField()
    full_name = models.CharField(max_length=100)
    first_name = models.CharField(max_length=50)
    family_name = models.CharField(max_length=50)
    profile_picture_url = models.CharField(max_length=100)
    default_locale = models.CharField(max_length=10)

class Application_User_Credentials(models.Model):
    Application_User = models.ForeignKey(Application_User, on_delete=models.CASCADE)
    token = models.CharField(max_length=500)
    refresh_token = models.CharField(max_length=500)
    token_uri = models.CharField(max_length=100)
    client_id = models.CharField(max_length=100)
    client_secret = models.CharField(max_length=100)
    scopes = models.CharField(max_length=500)

class Application_User_Messages(models.Model):
    Application_User = models.ForeignKey(Application_User, on_delete=models.CASCADE)
    message_id = models.CharField(max_length=100, primary_key=True)
    from_address = models.CharField(max_length=100)
    to_address = models.CharField(max_length=100)
    message_subject = models.CharField(max_length=500)
    message_body = models.CharField(max_length=1000)
    date_received = models.CharField(max_length=100, default=None)




