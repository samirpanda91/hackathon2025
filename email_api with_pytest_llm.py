from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import base64
import os
import pickle
import pytesseract
import spacy  # For PyTextRank
import pytextrank  # Extractive summarization
from PIL import Image
from pdf2image import convert_from_bytes
from transformers import pipeline  # AI Summarization (LLM-based)

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
SAVE_DIR = "attachments"

# Load PyTextRank with spaCy
nlp = spacy.load("en_core_web_sm")
nlp.add_pipe("textrank")

# Load LLM summarization model (Mistral 7B or GPT-based)
summarizer = pipeline("summarization", model="mistralai/Mistral-7B-Instruct-v0.1")

def authenticate_gmail():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            from google_auth_oauthlib.flow import InstalledAppFlow
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES, redirect_uri="http://localhost:8080/"
            )
            creds = flow.run_local_server(port=8080)

        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    return creds

def get_unread_emails():
    creds = authenticate_gmail()
    service = build('gmail', 'v1', credentials=creds)

    # Fetch unread emails
    results = service.users().messages().list(userId='me', q="is:unread label:inbox", maxResults=5).execute()
    messages = results.get('messages', [])

    unread_count = len(messages)
    print(f"Number of new unread emails in inbox: {unread_count}")

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

        full_text = ""

        parts = email_data["payload"].get("parts", [])
        for part in parts:
            if part["mimeType"] == "text/plain":
                body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
                print(f"Body:\n{body}\n{'-'*50}")
                full_text += body + "\n"

            if part["filename"] and "attachmentId" in part["body"]:
                attachment_id = part["body"]["attachmentId"]
                attachment = service.users().messages().attachments().get(userId="me", messageId=msg_id, id=attachment_id).execute()
                data = base64.urlsafe_b64decode(attachment["data"])

                file_path = os.path.join(SAVE_DIR, part["filename"])
                with open(file_path, "wb") as f:
                    f.write(data)
                print(f"Attachment saved: {file_path}")

                full_text += process_attachment(file_path) + "\n"

        if full_text:
            summarize_text(full_text)

def process_attachment(file_path):
    """Read text from TXT, PDF, or Image attachments."""
    extracted_text = ""
    if file_path.endswith(".txt"):
        extracted_text = read_txt(file_path)
    elif file_path.endswith(".pdf"):
        extracted_text = read_pdf(file_path)
    elif file_path.endswith((".png", ".jpg", ".jpeg", ".tiff", ".bmp")):
        extracted_text = read_image(file_path)
    return extracted_text

def read_txt(file_path):
    """Read text from a TXT file."""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    print(f"TXT Content:\n{content}\n{'-'*50}")
    return content

def read_pdf(file_path):
    """Extract text from PDF using OCR."""
    with open(file_path, "rb") as f:
        images = convert_from_bytes(f.read())
    extracted_text = ""
    for img in images:
        extracted_text += pytesseract.image_to_string(img) + "\n"
    
    print(f"PDF Extracted Text:\n{extracted_text}\n{'-'*50}")
    return extracted_text

def read_image(file_path):
    """Extract text from an image using OCR."""
    img = Image.open(file_path)
    text = pytesseract.image_to_string(img)
    print(f"Image Extracted Text:\n{text}\n{'-'*50}")
    return text

def summarize_text(text):
    """Summarizes extracted text using PyTextRank and an LLM model."""
    
    # Extractive summarization using PyTextRank (Important sentences)
    doc = nlp(text)
    key_sentences = " ".join([sent.text for sent in doc._.textrank.summary(limit_sentences=3)])

    print(f"Extractive Summary (PyTextRank):\n{key_sentences}\n{'-'*50}")

    # Abstractive summarization using Mistral 7B
    if len(text.split()) > 50:
        summary = summarizer(text, max_length=100, min_length=30, do_sample=False)[0]['summary_text']
        print(f"AI Summary (Mistral 7B):\n{summary}\n{'-'*50}")

if __name__ == "__main__":
    get_unread_emails()
    
    