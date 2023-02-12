from django.shortcuts import render
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Application_User, Application_User_Credentials, Application_User_Messages, Message_History
import google_auth_oauthlib.flow
import google.oauth2.credentials
from googleapiclient.discovery import build
import json
from google.oauth2 import id_token
from google.auth.transport import requests as google_auth_request
from .businesslogic.UserRegistrationManagement import UserRegistrationManagement as UserManagement
from .businesslogic.UserRegistrationManagement import LoginUserData
from .businesslogic.GmailServiceManagement import GmailServiceManagement as GmailService
from threading import Thread
import base64
import time
from django.http import JsonResponse
from django.core.paginator import EmptyPage, PageNotAnInteger, Paginator

# Create your views here.

CLIENT_ID = '113162519004-1m4s4dblkf5b2cpe9tdf4c4grbvoi53q.apps.googleusercontent.com'
SCOPES = 'openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/gmail.readonly'
PARSEDSCOPES = '[openid, https://www.googleapis.com/auth/userinfo.email, https://www.googleapis.com/auth/userinfo.profile, https://www.googleapis.com/auth/gmail.readonly]'
REDIRECT_URI = 'http://127.0.0.1:8000'

def signup(request):
    return render(request, 'authentication/signup.html');

def login(request):
    return render(request, 'authentication/login.html');

def home(request):
    page_number = request.GET.get('page')

    if page_number == None:
        t = Thread(target=fetch_emails, args=[request]);
        #t.run();
        t.start();

    result_list = list(Application_User_Messages.objects.all().values('message_id','from_address','to_address','message_subject','internal_date'))
    paginator = Paginator(result_list, 10)
    
    page_obj = paginator.get_page(page_number)
    return render(request, 'authentication/home.html', {'page_obj': page_obj});

@csrf_exempt
def validateauthcode(request):

    auth_code = json.loads(request.body.decode('utf8')).get('authentication_token')

    credentials = UserManagement.get_cerdetials_from_google(REDIRECT_URI, SCOPES, auth_code);

    credentialsDictionary = UserManagement.credentials_to_dict(credentials);
    parsedCredentialsFromDictionary = google.oauth2.credentials.Credentials(**credentialsDictionary);

    oauth = build('oauth2', 'v2', credentials=parsedCredentialsFromDictionary);
    userinfo = oauth.userinfo().get().execute();
    resultSet = Application_User.objects.filter(email=userinfo['email'])
    existingUserCount = len(resultSet);
    
    responseDict = {}
    
    if(existingUserCount == 0):
        registrationResponse = UserManagement.register_user(credentials, userinfo);

        resultSet = Application_User.objects.filter(email=userinfo['email'])
        userid = resultSet[0].id;
        credentialsResult = Application_User_Credentials.objects.filter(Application_User=userid);
        
        # To handle no credentials response from database (highly unlinkly scenario thus skipped)
        #credentialsResultLength = len(credentialsResult);

        credentialsResultList = list(credentialsResult.values())
        existingUserResultList = list(resultSet.values())

        request.session['Current_Application_User'] = existingUserResultList[0];
        request.session['Current_Application_User_Credentials'] = credentialsResultList[0];
        # success response
        responseDict["status"] = "success"
        responseDict["error_message"] = ""
        responseDict["redirect_uri"] = "/authentication/home"
    else:
        # error response
        responseDict["status"] = "error"
        responseDict["rrror_message"] = "User already registered"
        responseDict["redirect_uri"] = "/authentication/login"

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
    
    responseJson = json.dumps(responseDict)

    return HttpResponse(responseJson);

@csrf_exempt
def validate(request):

    # adding a artificial delay so google dosen't throw "used token too early errpr";
    time.sleep(2);

    data = request.body.decode('utf8')
    data = json.loads(data)
    dataInt = data.get('authentication_token')
    idinfo = id_token.verify_oauth2_token(dataInt, google_auth_request.Request(), CLIENT_ID)
    email_address = idinfo['email'] 

    resultSet = Application_User.objects.filter(email=email_address)
    existingUserCount = len(resultSet);
    responseDict = {}

    if(existingUserCount > 0):
        # fetch credentials from the database put it into a session maybe and send a success response to frontend so it can redirect user to homepage
        userid = resultSet[0].id;
        credentialsResult = Application_User_Credentials.objects.filter(Application_User=userid);
        
        # To handle no credentials response from database (highly unlinkly scenario thus skipped)
        #credentialsResultLength = len(credentialsResult);

        credentialsResultList = list(credentialsResult.values())
        existingUserResultList = list(resultSet.values())

        request.session['Current_Application_User'] = existingUserResultList[0];
        request.session['Current_Application_User_Credentials'] = credentialsResultList[0];

        # form success response
        responseDict["status"] = "success"
        responseDict["error_message"] = ""
        responseDict["redirect_uri"] = "/authentication/home"
    else:
        #form error response
        responseDict["status"] = "error"
        responseDict["rrror_message"] = "User not registered"
        responseDict["redirect_uri"] = "/authentication/signup"

    responseJson = json.dumps(responseDict)
    
    return HttpResponse(responseJson)

# [To-Do]
# fetching from history does not work
# also handle a scenario where history is not available at all in the response
def fetch_emails(request):

    currentUserInfo = LoginUserData(request.session)

    gmailService = GmailService.getServiceFromSession(currentUserInfo);
    messageHistory = GmailService.getUserHistory(currentUserInfo, gmailService);
    gmailMessagesRequest = messageHistory.gmailMessagesRequest;

    itrCount = 0;
    isSaveMessageHistory:bool;

    while gmailMessagesRequest is not None:
        itrCount += 1;
        if itrCount == 1: isSaveMessageHistory = True
        else: isSaveMessageHistory = False
        try:
            messagesResponse = gmailMessagesRequest.execute();
        except:
            continue

        if messageHistory.fetchingFromHistory:
            if messagesResponse.get('history') is not None:
                historyArray = messagesResponse['history']
                gmailMessagesRequest = gmailService.users().history().list_next(gmailMessagesRequest, messagesResponse)
            
                for history in historyArray:
                    messagesArray = history['messages']
                    GmailService.processMessageArray(messagesArray, currentUserInfo, gmailService, isSaveMessageHistory);

        else:
            messagesArray = messagesResponse['messages']
            gmailMessagesRequest = gmailService.users().messages().list_next(gmailMessagesRequest, messagesResponse)
            GmailService.processMessageArray(messagesArray, currentUserInfo, gmailService, isSaveMessageHistory)

@csrf_exempt
def user_emails(request):
    result_list = list(Application_User_Messages.objects.all().values('message_id','from_address','to_address','message_subject','internal_date'))
    return JsonResponse(result_list, safe=False)

@csrf_exempt
def paginated_user_emails(request):
    page_number = request.GET.get('page')
    result_list = list(Application_User_Messages.objects.all().values('message_id','from_address','to_address','message_subject','internal_date'))
    result_list.sort(reverse=True, key=myFunc)

    paginator = Paginator(result_list, 50)
    page_obj = paginator.get_page(page_number)
   
    try:
        objects = paginator.page(page_number)
    except PageNotAnInteger:
        objects = paginator.page(1)
    except EmptyPage:
        objects = paginator.page(paginator.num_pages)
    
    data = {
            'current' : page_number,
            'has_previous' : objects.has_previous(),
            'has_next' : objects.has_next(),
            'previous_page': objects.has_previous() and objects.previous_page_number() or None,
            'next_page': objects.has_next() and objects.next_page_number() or None,
            'num_pages': paginator.num_pages,
            'data': list(objects)
        }
    #return data
    return JsonResponse(data, safe=False)

def myFunc(e):
  return e['internal_date']
