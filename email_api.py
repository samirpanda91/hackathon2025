from googleapiclient.discovery import build
from google.oauth2 import service_account
from google.auth.transport.requests import Request
import base64
import os
import pickle
import email

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    creds = None
    # Load saved credentials (if available)
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    # If credentials are invalid or not found, authenticate using OAuth
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            from google_auth_oauthlib.flow import InstalledAppFlow
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        
        # Save the credentials for future use
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    return creds

def get_unread_emails():
    creds = authenticate_gmail()
    service = build('gmail', 'v1', credentials=creds)

    # Search for unread emails
    results = service.users().messages().list(userId='me', q="is:unread", maxResults=10).execute()
    messages = results.get('messages', [])

    if not messages:
        print("No new unread emails.")
        return

    for msg in messages:
        msg_id = msg['id']
        email_data = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

        headers = email_data["payload"]["headers"]
        subject = next(header["value"] for header in headers if header["name"] == "Subject")
        sender = next(header["value"] for header in headers if header["name"] == "From")

        # Decode email body
        for part in email_data["payload"]["parts"]:
            if part["mimeType"] == "text/plain":
                body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
                print(f"From: {sender}\nSubject: {subject}\nBody:\n{body}\n{'-'*50}")
                break

if __name__ == "__main__":
    get_unread_emails()