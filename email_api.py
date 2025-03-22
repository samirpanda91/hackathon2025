from google_auth_oauthlib.flow import InstalledAppFlow

flow = InstalledAppFlow.from_client_secrets_file(
    'credentials.json', SCOPES, redirect_uri="http://localhost:8080/"
)
creds = flow.run_local_server(port=8080)