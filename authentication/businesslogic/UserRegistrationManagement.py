from ..models import Application_User, Application_User_Credentials, Application_User_Messages
import google.oauth2.credentials
import google_auth_oauthlib.flow

class LoginUserData:
    currentUser: any
    currentUserCredentials: any
    
    def __init__(self, session) -> None:
        self.info = session['Current_Application_User']
        self.credentials = session['Current_Application_User_Credentials']


class UserRegistrationManagement:

    @staticmethod
    def credentials_to_dict(credentials):
        return {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret
            #'scopes': credentials.scopes
        }

    @staticmethod
    def register_user( 
        credentials: google.oauth2.credentials.Credentials,
        userinfo: dict ) -> int:

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


        credentialsDto = Application_User_Credentials();
        credentialsDto.Application_User = Application_User.objects.get(pk=applicationUserDto.id);
        credentialsDto.token = credentials.token;
        credentialsDto.refresh_token = credentials.refresh_token;
        credentialsDto.token_uri = credentials.token_uri;
        credentialsDto.client_id = credentials.client_id;
        credentialsDto.client_secret = credentials.client_secret;
        credentialsDto.scopes = credentials.scopes;
        credentialsDto.save();

        return 0

    @staticmethod
    def get_cerdetials_from_google(redirectUri: str, authenticationScopes: str, auth_code: str) -> google.oauth2.credentials.Credentials:
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=authenticationScopes
        );
    
        flow.redirect_uri = redirectUri;
        flow.fetch_token(code=auth_code);
        
        return flow.credentials

