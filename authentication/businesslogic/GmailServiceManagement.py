from googleapiclient.discovery import build
import google_auth_oauthlib.flow
import google.oauth2.credentials
from ..models import *

class MessageHistoryResponse:
    fetchingFromHistory :bool;
    gmailMessagesRequest = None;

class SaveUserMessageResponse:
    messageDto :Application_User_Messages;
    isSuccessful :bool;
    errorMessage :str;
    rawResult = None;

class GmailServiceManagement:

    @staticmethod
    def getServiceFromSession(session):
        # fetch credentials from session       
        # fetch application_user from session

        application_user = session['Current_Application_User'];
        credentialsDictionary = session['Current_Application_User_Credentials'];

        manuallyCreatedCredentials = {
            'token' : credentialsDictionary.get('token'),
            'refresh_token' : credentialsDictionary.get('refresh_token'),
            'token_uri' : credentialsDictionary.get('token_uri'),
            'client_id' : credentialsDictionary.get('client_id'),
            'client_secret' : credentialsDictionary.get('client_secret')
        }

        parsedCredentials = google.oauth2.credentials.Credentials(**manuallyCreatedCredentials);

        return build('gmail', 'v1', credentials=parsedCredentials);
    
    @staticmethod
    def getUserHistory(session, gmailService):
        messageHistory = MessageHistoryResponse()
        fetchingFromHistory :bool

        application_user = session['Current_Application_User'];
        historyRecord = Message_History.objects.filter(Application_User=application_user.get('id'));

        if(len(historyRecord) > 0):
            historyRecordList = list(historyRecord.values())
            fetchingFromHistory = True;
            fetchedHistoryId = historyRecordList[0].get('history_id');
            gmailMessagesRequest = gmailService.users().history().list(userId='me', startHistoryId=fetchedHistoryId)
        else:
            fetchingFromHistory = False;
            gmailMessagesRequest = gmailService.users().messages().list(userId='me', includeSpamTrash=False, maxResults=100)
        
        messageHistory.gmailMessagesRequest = gmailMessagesRequest;
        messageHistory.fetchingFromHistory = fetchingFromHistory;
        return messageHistory;

    @staticmethod
    def saveUserMessage(session, message, gmailService):
        application_user = session['Current_Application_User'];
        messageDto = Application_User_Messages();
        response = SaveUserMessageResponse();

        messageDto.Application_User = Application_User.objects.get(pk=application_user.get('id'));
        parsedId = message['id']
        parsedThreadId = message['threadId']
        #gmailMessagesDetailRequest = gmailService.users().messages().get(userId='me', id=parsedId, format="raw");
        gmailMessagesDetailRequest = gmailService.users().messages().get(userId='me', id=parsedId, format="full");
        #tempResult = gmailMessagesDetailRequest.execute();
        tempResult = gmailMessagesDetailRequest.execute();
        #rawBody = tempResult['raw'] # when format = raw
        #decodedRawBody = base64.urlsafe_b64decode(rawBody + '=' * (4 - len(rawBody) % 4));
        #decodedRawBody = base64.urlsafe_b64decode(rawBody + '=' * (4 - len(rawBody) % 4)).decode('utf-8');
        body = tempResult.get('snippet');
        body = tempResult['snippet'];
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
            response.messageDto = messageDto;
            response.isSuccessful = True;
            response.rawResult = tempResult;
            return response;
        except Exception as ex:
            print(ex)
            response.isSuccessful = False;
            return response;


