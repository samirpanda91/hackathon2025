import os
import base64
import pickle
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from email import message_from_bytes
from PyPDF2 import PdfReader

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
SAVE_DIR = "attachments"  # Directory to save attachments

def authenticate_gmail():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=8080)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    return creds

def get_unread_emails():
    creds = authenticate_gmail()
    service = build('gmail', 'v1', credentials=creds)

    results = service.users().messages().list(userId='me', q="is:unread", maxResults=5).execute()
    messages = results.get('messages', [])

    if not messages:
        print("No new unread emails.")
        return

    os.makedirs(SAVE_DIR, exist_ok=True)  # Ensure attachment folder exists

    for msg in messages:
        msg_id = msg['id']
        email_data = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

        headers = email_data["payload"]["headers"]
        subject = next(header["value"] for header in headers if header["name"] == "Subject")
        sender = next(header["value"] for header in headers if header["name"] == "From")

        print(f"From: {sender}\nSubject: {subject}")

        parts = email_data["payload"].get("parts", [])
        for part in parts:
            if part["mimeType"] == "text/plain":
                body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
                print(f"Body:\n{body}\n{'-'*50}")
            
            # Handling attachments
            if part["filename"] and "attachmentId" in part["body"]:
                attachment_id = part["body"]["attachmentId"]
                attachment = service.users().messages().attachments().get(userId="me", messageId=msg_id, id=attachment_id).execute()
                data = base64.urlsafe_b64decode(attachment["data"])

                file_path = os.path.join(SAVE_DIR, part["filename"])
                with open(file_path, "wb") as f:
                    f.write(data)
                print(f"Attachment saved: {file_path}")

                # Process the attachment if it's a TXT or PDF
                if file_path.endswith(".txt"):
                    read_txt(file_path)
                elif file_path.endswith(".pdf"):
                    read_pdf(file_path)

def read_txt(file_path):
    """Read and print the contents of a TXT file."""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    print(f"TXT Content:\n{content}\n{'-'*50}")

def read_pdf(file_path):
    """Read and print the contents of a PDF file."""
    with open(file_path, "rb") as f:
        reader = PdfReader(f)
        text = "\n".join([page.extract_text() for page in reader.pages if page.extract_text()])
    print(f"PDF Content:\n{text}\n{'-'*50}")

if __name__ == "__main__":
    get_unread_emails()