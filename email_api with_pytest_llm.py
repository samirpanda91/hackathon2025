# from googleapiclient.discovery import build
# from google.auth.transport.requests import Request
# import base64
# import os
# import pickle
# import pytesseract
# from PIL import Image
# from pdf2image import convert_from_bytes
# from transformers import pipeline
# from nltk.tokenize import sent_tokenize
# import requests  # For Jira API

# SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
# SAVE_DIR = "attachments"

# # Jira Configuration
# JIRA_URL = "https://hackathon202501.atlassian.net"
# JIRA_USERNAME = "samir.panda10@gmail.com"
# JIRA_API_TOKEN = "ATATT3xFfGF08YrQF11HwIEa3uogjmNAlbDd7VrNdR7BuRXcugjyMb71gXI-v6LefcUrfr_YpHks3dUlgaRG6tHjNoHHRTaIhV88P7-U4y3s9mXDB2Q3fcYhWi_YLxcHQMzZISNZ29tx-zn2fy0IRdLKKKQNYJCgFeqE5dhDjg1HRH7DmryQpGc=5BA9213B"
# JIRA_PROJECT_KEY = "HAC"

# # Load AI summarization model
# summarizer = pipeline("summarization", model="facebook/bart-large-cnn")

# def authenticate_gmail():
#     creds = None
#     if os.path.exists('token.pickle'):
#         with open('token.pickle', 'rb') as token:
#             creds = pickle.load(token)

#     if not creds or not creds.valid:
#         if creds and creds.expired and creds.refresh_token:
#             creds.refresh(Request())
#         else:
#             from google_auth_oauthlib.flow import InstalledAppFlow
#             flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
#             creds = flow.run_local_server(port=8080)

#         with open('token.pickle', 'wb') as token:
#             pickle.dump(creds, token)

#     return creds

# def get_unread_emails():
#     creds = authenticate_gmail()
#     service = build('gmail', 'v1', credentials=creds)

#     results = service.users().messages().list(userId='me', q="is:unread label:inbox", maxResults=5).execute()
#     messages = results.get('messages', [])

#     if not messages:
#         print("No new unread emails.")
#         return

#     os.makedirs(SAVE_DIR, exist_ok=True)

#     for msg in messages:
#         msg_id = msg['id']
#         email_data = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

#         headers = email_data["payload"]["headers"]
#         subject = next(header["value"] for header in headers if header["name"] == "Subject")
#         sender = next(header["value"] for header in headers if header["name"] == "From")

#         print(f"From: {sender}\nSubject: {subject}")

#         body = None
#         parts = email_data["payload"].get("parts", [])
#         for part in parts:
#             if part["mimeType"] == "text/plain":
#                 body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
#                 print(f"Body:\n{body}\n{'-'*50}")
#                 summary = summarize_text(body)  
#                 create_jira_ticket(subject, sender, summary)

#             if part.get("filename") and "attachmentId" in part["body"]:
#                 attachment_id = part["body"]["attachmentId"]
#                 attachment = service.users().messages().attachments().get(userId="me", messageId=msg_id, id=attachment_id).execute()
#                 data = base64.urlsafe_b64decode(attachment["data"])

#                 file_path = os.path.join(SAVE_DIR, part["filename"])
#                 with open(file_path, "wb") as f:
#                     f.write(data)
#                 print(f"Attachment saved: {file_path}")

#                 process_attachment(file_path, subject, sender)

#         # mark_email_as_read(service, msg_id)

# def process_attachment(file_path, subject, sender):
#     extracted_text = ""
#     if file_path.endswith(".txt"):
#         with open(file_path, "r", encoding="utf-8") as f:
#             extracted_text = f.read()
#     elif file_path.endswith(".pdf"):
#         extracted_text = extract_text_from_pdf(file_path)
#     elif file_path.endswith((".png", ".jpg", ".jpeg", ".tiff", ".bmp")):
#         extracted_text = extract_text_from_image(file_path)

#     if extracted_text:
#         summary = summarize_text(extracted_text)
#         create_jira_ticket(subject, sender, summary)

# def extract_text_from_pdf(file_path):
#     with open(file_path, "rb") as f:
#         images = convert_from_bytes(f.read())
#     extracted_text = "\n".join(pytesseract.image_to_string(img) for img in images)
#     print(f"PDF Extracted Text:\n{extracted_text}\n{'-'*50}")
#     return extracted_text

# def extract_text_from_image(file_path):
#     img = Image.open(file_path)
#     text = pytesseract.image_to_string(img)
#     print(f"Image Extracted Text:\n{text}\n{'-'*50}")
#     return text

# # def summarize_text(text):
# #     """Summarizes extracted text using AI."""
# #     if len(text.split()) < 50:  # If text is too short, return as is
# #         return text.strip()

# #     text_chunks = [text] if len(sent_tokenize(text)) < 10 else [" ".join(sent_tokenize(text)[:10])]
# #     summary = summarizer(text_chunks[0], max_length=100, min_length=30, do_sample=False)[0]['summary_text']

# #     print(f"AI Summary:\n{summary}\n{'-'*50}")
# #     return summary

# from openai import OpenAI
# import openai

# client = OpenAI()

# client.api_key = "ysk-proj-M63ARMmiOW2CS0lxVIz-7H3Z0LkJnSS7Mn5KCmIcEGReR8l5lJlHSpa0a8k5zaXqd-nK2kI3AcT3BlbkFJ5l-94hyt8UJETFsOcsAdPDHPEGVVVwogCBY6awwfIiIvg5UfwCflJ5gZ7onrF4EDnDb-RU7dAA"

# def summarize_text(text):
#     """Summarizes extracted text using OpenAI GPT-4."""
#     if len(text.split()) < 50:  # If text is too short, return as is
#         return text.strip()

#     try:
#         response = client.chat.completions.create(model="gpt-4",
#         messages=[
#             {"role": "system", "content": "You are an AI assistant that summarizes text."},
#             {"role": "user", "content": f"Summarize this text:\n\n{text}"}
#         ],
#         max_tokens=100)
#         summary = response.choices[0].message.content.strip()
#         print(f"AI Summary:\n{summary}\n{'-'*50}")
#         return summary

#     except Exception as e:
#         print(f"OpenAI API Error: {e}")
#         return "Summarization failed"


# def create_jira_ticket(subject, sender, summary):
#     """Creates a Jira ticket with email summary."""
#     url = f"{JIRA_URL}/rest/api/3/issue"
#     auth = (JIRA_USERNAME, JIRA_API_TOKEN)

#     headers = {
#         "Accept": "application/json",
#         "Content-Type": "application/json"
#     }

#     payload = {
#         "fields": {
#             "project": {"key": JIRA_PROJECT_KEY},
#             "summary": subject,
#             "description": {
#                     "type": "doc",
#                     "version": 1,
#                     "content": [
#                         {
#                         "type": "paragraph",
#                         "content": [
#                             {
#                             "type": "text",
#                             "text": summary,
#                             }
#                         ]
#                         }
#                     ]
#                     },
#             "issuetype": {"name": "Task"}
#         }
#     }

#     response = requests.post(url, json=payload, headers=headers, auth=auth)

#     if response.status_code == 201:
#         print(f"Jira Ticket Created: {response.json().key}\n{'-'*50}")
#     else:
#         print(f"Failed to create Jira ticket: {response.text}\n{'-'*50}")

# def mark_email_as_read(service, msg_id):
#     """Marks an email as read in Gmail."""
#     service.users().messages().modify(userId='me', id=msg_id, body={"removeLabelIds": ["UNREAD"]}).execute()
#     print(f"Marked email {msg_id} as read.\n{'-'*50}")

# if __name__ == "__main__":
#     get_unread_emails()








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
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Jira Configuration
JIRA_URL = "https://hackathon202501.atlassian.net"
JIRA_USERNAME = "samir.panda10@gmail.com"
JIRA_API_TOKEN = "ATATT3xFfGF08YrQF11HwIEa3uogjmNAlbDd7VrNdR7BuRXcugjyMb71gXI-v6LefcUrfr_YpHks3dUlgaRG6tHjNoHHRTaIhV88P7-U4y3s9mXDB2Q3fcYhWi_YLxcHQMzZISNZ29tx-zn2fy0IRdLKKKQNYJCgFeqE5dhDjg1HRH7DmryQpGc=5BA9213B"
JIRA_PROJECT_KEY = "HAC"

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

        # mark_email_as_read(service, msg_id)

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
            "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                        "type": "paragraph",
                        "content": [
                            {
                            "type": "text",
                            "text": summary,
                            }
                        ]
                        }
                    ]
                    },
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
