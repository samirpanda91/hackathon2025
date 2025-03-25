import os
import base64
import pickle
import requests
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow

# Gmail API Scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
SAVE_DIR = "attachments"

# OpenAI API Key
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "your-openai-api-key")

# Jira Configuration
JIRA_URL = "https://your-jira-instance.atlassian.net"
JIRA_USERNAME = "your-email@example.com"
JIRA_API_TOKEN = "your-api-token"
JIRA_PROJECT_KEY = "PROJECT"

def authenticate_gmail():
    """Authenticate and return Gmail API service."""
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

    return build('gmail', 'v1', credentials=creds)

def get_unread_emails():
    """Fetch unread emails, summarize them, and create Jira tickets."""
    service = authenticate_gmail()
    results = service.users().messages().list(userId='me', q="is:unread label:inbox", maxResults=5).execute()
    messages = results.get('messages', [])

    if not messages:
        print("No new unread emails.")
        return

    os.makedirs(SAVE_DIR, exist_ok=True)

    for msg in messages:
        msg_id = msg['id']
        email_data = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

        headers = email_data["payload"]["headers"]
        subject = next(header["value"] for header in headers if header["name"] == "Subject")
        sender = next(header["value"] for header in headers if header["name"] == "From")

        print(f"From: {sender}\nSubject: {subject}")

        body = None
        parts = email_data["payload"].get("parts", [])
        for part in parts:
            if part["mimeType"] == "text/plain":
                body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
                print(f"Body:\n{body}\n{'-'*50}")
                summary = summarize_text(body)  
                create_jira_ticket(subject, sender, summary)

            if part.get("filename") and "attachmentId" in part["body"]:
                attachment_id = part["body"]["attachmentId"]
                attachment = service.users().messages().attachments().get(userId="me", messageId=msg_id, id=attachment_id).execute()
                data = base64.urlsafe_b64decode(attachment["data"])

                file_path = os.path.join(SAVE_DIR, part["filename"])
                with open(file_path, "wb") as f:
                    f.write(data)
                print(f"Attachment saved: {file_path}")

        mark_email_as_read(service, msg_id)

def summarize_text(text):
    """Summarize text using OpenAI GPT."""
    if len(text.split()) < 50:  # If text is too short, return as is
        return text.strip()

    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
        json={
            "model": "gpt-4-turbo",
            "messages": [{"role": "system", "content": "Summarize the following text."}, {"role": "user", "content": text}],
            "max_tokens": 100
        },
    )

    if response.status_code == 200:
        return response.json()["choices"][0]["message"]["content"].strip()
    else:
        print(f"OpenAI API Error: {response.text}")
        return text

def create_jira_ticket(subject, sender, summary):
    """Create a Jira ticket with the summarized email content."""
    url = f"{JIRA_URL}/rest/api/3/issue"
    auth = (JIRA_USERNAME, JIRA_API_TOKEN)

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": subject,
            "description": f"**From:** {sender}\n\n**Summary:**\n{summary}",
            "issuetype": {"name": "Task"}
        }
    }

    response = requests.post(url, json=payload, headers=headers, auth=auth)

    if response.status_code == 201:
        print(f"Jira Ticket Created: {response.json()['key']}\n{'-'*50}")
    else:
        print(f"Failed to create Jira ticket: {response.text}\n{'-'*50}")

def mark_email_as_read(service, msg_id):
    """Mark an email as read in Gmail."""
    service.users().messages().modify(userId='me', id=msg_id, body={"removeLabelIds": ["UNREAD"]}).execute()
    print(f"Marked email {msg_id} as read.\n{'-'*50}")

if __name__ == "__main__":
    get_unread_emails()