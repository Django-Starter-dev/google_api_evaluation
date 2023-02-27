from googleapiclient.discovery import build
import google_auth_oauthlib.flow
import google.oauth2.credentials
from ..models import *
from ..businesslogic.UserRegistrationManagement import LoginUserData

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
    def getServiceFromSession(currentUser:LoginUserData):
        # fetch credentials from session       
        # fetch application_user from session

        manuallyCreatedCredentials = {
            'token' : currentUser.credentials.get('token'),
            'refresh_token' : currentUser.credentials.get('refresh_token'),
            'token_uri' : currentUser.credentials.get('token_uri'),
            'client_id' : currentUser.credentials.get('client_id'),
            'client_secret' : currentUser.credentials.get('client_secret')
        }

        parsedCredentials = google.oauth2.credentials.Credentials(**manuallyCreatedCredentials)

        return build('gmail', 'v1', credentials=parsedCredentials);
    
    @staticmethod
    def getUserHistory(currentUser:LoginUserData, gmailService):
        messageHistory = MessageHistoryResponse()
        fetchingFromHistory :bool

        historyRecord = Message_History.objects.filter(Application_User=currentUser.info.get('id'))

        if(len(historyRecord) > 0):
            historyRecordList = list(historyRecord.values())
            fetchingFromHistory = True;
            fetchedHistoryId = historyRecordList[0].get('history_id');
            gmailMessagesRequest = gmailService.users().history().list(userId='me', historyTypes='messageAdded', startHistoryId=fetchedHistoryId)
        else:
            fetchingFromHistory = False;
            gmailMessagesRequest = gmailService.users().messages().list(userId='me', includeSpamTrash=False, maxResults=100)
        
        messageHistory.gmailMessagesRequest = gmailMessagesRequest;
        messageHistory.fetchingFromHistory = fetchingFromHistory;
        return messageHistory;

    @staticmethod
    def saveUserMessage(currentUser:LoginUserData, message, gmailService, isFetchingFromHistory:bool):
        messageDto = Application_User_Messages();
        response = SaveUserMessageResponse();

        messageDto.Application_User = Application_User.objects.get(pk=currentUser.info.get('id'));
        if isFetchingFromHistory:
            parsedId = message.get('message')['id']
            parsedThreadId = message.get('threadId')
        else:
            parsedId = message['id']
            parsedThreadId = message['threadId']
        
        #gmailMessagesDetailRequest = gmailService.users().messages().get(userId='me', id=parsedId, format="raw");
        gmailMessagesDetailRequest = gmailService.users().messages().get(userId='me', id=parsedId, format="full");
        #tempResult = gmailMessagesDetailRequest.execute();
        tempResult = gmailMessagesDetailRequest.execute();
        #rawBody = tempResult['raw'] # when format = raw
        #decodedRawBody = base64.urlsafe_b64decode(rawBody + '=' * (4 - len(rawBody) % 4));
        #decodedRawBody = base64.urlsafe_b64decode(rawBody + '=' * (4 - len(rawBody) % 4)).decode('utf-8');
        #body = tempResult.get('snippet');
        body = tempResult['snippet'];
        messageDto.message_body = body;
        headersList = tempResult['payload']['headers']
        messageDto.internal_date = tempResult['internalDate']

        for header in headersList:
            if(header['name'] == "Message-ID"):
                messageId = header['value']
                messageDto.message_id = messageId;
            if(header['name'] == "Date"):
                dateReceived = header['value']
                messageDto.date_received = dateReceived;
            if(header['name'] == "Subject"):
                subject = header['value']
                if len(subject) > 1000:
                    subject = subject[:1000]
                messageDto.message_subject = subject;
            if(header['name'] == "From"):
                fromAddress = header['value']
                if len(fromAddress) > 1000:
                    fromAddress = fromAddress[:1000]
                messageDto.from_address = fromAddress;
            if(header['name'] == "To"):
                toAddress = header['value']
                if len(toAddress) > 1000:
                    toAddress = toAddress[:1000]
                messageDto.to_address = toAddress;
        
        try:
            messageDto.message_id = parsedId;
            response.messageDto = messageDto;
            response.isSuccessful = True;
            response.rawResult = tempResult;
            return response;
        except Exception as ex:
            print(ex)
            response.isSuccessful = False;
            return response;

    @staticmethod
    def saveUserMessageHistory(saveUserMessageResoponse):
        #resultSet = Application_User.objects.filter(email=userinfo['email'])
        #existingUserCount = len(resultSet);
        #message_history = Message_History();
        message_history = Message_History.objects.filter(Application_User=saveUserMessageResoponse.messageDto.Application_User)
        message_history_count = len(message_history);

        if message_history_count == 0:
            message_history = Message_History();
            message_history.Application_User = saveUserMessageResoponse.messageDto.Application_User
            message_history.history_id = saveUserMessageResoponse.rawResult['historyId'] #tempResult['historyId'];
            message_history.save();
        else:
            message_history.update(history_id=saveUserMessageResoponse.rawResult['historyId'])
            Message_History.objects.filter(Application_User=saveUserMessageResoponse.messageDto.Application_User).update(history_id=saveUserMessageResoponse.rawResult['historyId'])
            #message_history[0].history_id = saveUserMessageResoponse.rawResult['historyId'] #tempResult['historyId'];
            #message_history[0].save();
     
    @staticmethod
    def updateUserMessageHistory(historyId: int, currentUser: LoginUserData):
        message_history = Message_History.objects.filter(Application_User = currentUser.info.get('id'))
        message_history_count = len(message_history)
        if message_history_count == 1:
            message_history.update(history_id=historyId)
            #Message_History.objects.filter(Application_User = currentUser.info.get('id')).update(history_id=historyId)

    @staticmethod
    def processMessageArray(messagesArray, currentUser:LoginUserData, gmailService, isSaveMessageHistory, isFetchingFromHistory:bool):

        messageList:list = [];

        for message in messagesArray:
            saveUserMessageResoponse = GmailServiceManagement.saveUserMessage(currentUser, message, gmailService, isFetchingFromHistory)
            messageList.append(saveUserMessageResoponse.messageDto)

            if (message == messagesArray[0]) & isSaveMessageHistory: 
                GmailServiceManagement.saveUserMessageHistory(saveUserMessageResoponse);
        
        messageCount = len(messageList)
        if messageCount > 0:
            Application_User_Messages.objects.bulk_create(messageList, len(messageList)) 




