from django.shortcuts import render
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Application_User, Application_User_Credentials, Application_User_Messages
import google_auth_oauthlib.flow
import google.oauth2.credentials
from googleapiclient.discovery import build
import json
from google.oauth2 import id_token
from google.auth.transport import requests as google_auth_request

# Create your views here.

CLIENT_ID = '113162519004-1m4s4dblkf5b2cpe9tdf4c4grbvoi53q.apps.googleusercontent.com'
SCOPES = 'openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/gmail.readonly'
PARSEDSCOPES = '[openid, https://www.googleapis.com/auth/userinfo.email, https://www.googleapis.com/auth/userinfo.profile, https://www.googleapis.com/auth/gmail.readonly]'
REDIRECT_URI = 'http://127.0.0.1:8000'

def signup(request):
    return render(request, 'authentication/signup.html');

def login(request):
    return render(request, 'authentication/login.html');

@csrf_exempt
def validateauthcode(request):

    data = request.body.decode('utf8')
    data = json.loads(data)
    auth_code = data.get('authentication_token')

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=SCOPES
    )
    flow.redirect_uri = REDIRECT_URI;
    flow.fetch_token(code=auth_code)
    credentials = flow.credentials

    # structure to be used when authenticating offline (without user interaction)
    # [To-Do] create a method to convert credentials to dictionary
    credentialsDictionary = {
        'token' : 'ya29.a0AeTM1ieabsSiBfEpaHpZqDcKYlEMhHf_JLHHrEvTKvN6pE7SjdogkCzDl5mnforTOpjxSy_or-qq8Jj3Ab0Qqn194XFKB-8TB7UNkLgJbsm8eE1fBRt-_88kG-lMUke5Eo7NKYo_X87312YxbEA2HuZ-4wAgaCgYKATQSARASFQHWtWOmMqf3LYW0DoBgxbs2HrkPdQ0163', # string
        'refresh_token' : '1//0gCyYEVgfAxLbCgYIARAAGBASNwF-L9IrVwZT9n1RrkGXiwdw3sQ1dPoaIwaDQXszvveKiwZ1A19dSmzwwLSoe8QbAsX27hEi3zo', # string
        'token_uri' : credentials.token_uri, # string
        'client_id' : credentials.client_id, # string
        'client_secret' : credentials.client_secret # string
        #'scopes' : credentials.scopes # string
    };
    
    credentialsDto = Application_User_Credentials();
    credentialsDto.token = credentials.token;
    credentialsDto.refresh_token = credentials.refresh_token;
    credentialsDto.token_uri = credentials.token_uri;
    credentialsDto.client_id = credentials.client_id;
    credentialsDto.client_secret = credentials.client_secret;
    credentialsDto.scopes = credentials.scopes;
    
    #request.session['credentials'] = credentials_to_dict(credentials);
    parsedCredentialsFromDictionary = google.oauth2.credentials.Credentials(**credentialsDictionary);

    #oauth = build('oauth2', 'v2', credentials=credentials);
    oauth = build('oauth2', 'v2', credentials=parsedCredentialsFromDictionary);
    
    userinfo = oauth.userinfo().get().execute();

    # [To-Do] check if the user is already registered
        # filter using email
        # if user is not registered
            # create a entry in Application_User and Application_User_Credentials
        # else
            # send error (User already registered)

    resultSet = Application_User.objects.filter(email=userinfo['email'])

    existingUserCount = len(resultSet);
    
    if(existingUserCount == 0):
        # Insert the new user in database
        # [To-Do] create a method where you send userinfo and credentail DTO
        # and it inserts everythong in database
        applicationUserDto = Application_User();
        applicationUserDto.id = userinfo['id'];
        applicationUserDto.email = userinfo['email'];
        applicationUserDto.is_email_verified = userinfo['verified_email'];
        applicationUserDto.full_name = userinfo['name'];
        applicationUserDto.first_name = userinfo['given_name'];
        applicationUserDto.family_name = userinfo['family_name'];
        applicationUserDto.profile_picture_url = userinfo['picture'];
        applicationUserDto.default_locale = userinfo['locale'];
        applicationUserDto.save();

        # Inseert user credential in database as well with foreign key
        credentialsDto.Application_User = Application_User.objects.get(pk=applicationUserDto.id);
        credentialsDto.save();
    else:
        #Throw someking of error
        print("user already registered")

    if (False):
        # call gmail api for testing 
        # [To-Do] this needs to be transffered from here to probably home screen or some external service
        gmailService = build('gmail', 'v1', credentials=credentials)
        gmailMessagesRequest = gmailService.users().messages().list(userId='me', includeSpamTrash=False, maxResults=100)

        while gmailMessagesRequest is not None:
            messagesResponse = gmailMessagesRequest.execute()
            
            messagesArray = messagesResponse['messages']

            for message in messagesArray:
                messageDto = Application_User_Messages();
                messageDto.Application_User = Application_User.objects.get(pk=resultSet[0].id);
                parsedId = message['id']
                parsedThreadId = message['threadId']
                gmailMessagesDetailRequest = gmailService.users().messages().get(userId='me', id=parsedId)
                tempResult = gmailMessagesDetailRequest.execute()

                body = tempResult['snippet']
                messageDto.message_body = body;

                headersList = tempResult['payload']['headers']

                for header in headersList:
                    if(header['name'] == "Message-ID"):
                        messageId = header['value']
                        messageDto.message_id = messageId;
                    if(header['name'] == "Date"):
                        dateReceived = header['value']
                        messageDto.date_received = dateReceived;
                    if(header['name'] == "Subject"):
                        subject = header['value']
                        messageDto.message_subject = subject;
                    if(header['name'] == "From"):
                        fromAddress = header['value']
                        messageDto.from_address = fromAddress;
                    if(header['name'] == "To"):
                        toAddress = header['value']
                        messageDto.to_address = toAddress;

                try:
                    messageDto.save();
                except:
                    continue;

            gmailMessagesRequest = gmailService.users().messages().list_next(gmailMessagesRequest, messagesResponse)
    

    return HttpResponse();

# [To-Do] test the endpoint after javascript origin has been verified
@csrf_exempt
def validate(request):
    data = request.body.decode('utf8')
    data = json.loads(data)
    dataInt = data.get('authentication_token')
    idinfo = id_token.verify_oauth2_token(dataInt, google_auth_request.Request(), CLIENT_ID)
    #userid = idinfo['sub']
    email_address = idinfo['email'] 

    # after you get the email address of user that is trying to log in
        # check it against Application_User
            # if you get a hit load the user and it's credentials 
            # else send error ()

    resultSet = Application_User.objects.filter(email=email_address)
    existingUserCount = len(resultSet);
    responseDict = {}

    if(existingUserCount > 0):
        # fetch credentials from the database put it into a session maybe and send a success response to frontend so it can redirect user to homepage
        userid = resultSet[0].id;
        credentialsResult = Application_User_Credentials.objects.filter(Application_User=userid);
        credentialsResultLength = len(credentialsResult);

        credentialsResultList = list(credentialsResult.values())
        existingUserResultList = list(resultSet.values())

        request.session['Current_Application_User'] = credentialsResultList[0];
        request.session['Current_Application_User_Credentials'] = existingUserResultList[0];
        responseDict["Status"] = "success"
        responseDict["ErrorMessage"] = ""
    else:
        responseDict["Status"] = "error"
        responseDict["ErrorMessage"] = "User not registered"

        # if everything was successful redirect user to home screen

    responseJson = json.dumps(responseDict)
    
    return HttpResponse(responseJson)

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}
