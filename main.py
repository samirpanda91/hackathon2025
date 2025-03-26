import base64
import hashlib
import io
import json
import os
import pickle
import re
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Set

import PyPDF2
import google.generativeai as genai
import pytesseract
import pytz
import uvicorn
from PIL import Image
from fastapi import FastAPI, HTTPException
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from pdf2image import convert_from_bytes
from pydantic import BaseModel

# Configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
MAX_CONTENT_LENGTH = 30000
POLL_INTERVAL = 15
DUPLICATE_WINDOW = timedelta(hours=24)

# Request types and subtypes
REQUEST_TYPES = [
    "Adjustment",
    "AU Transfer",
    "Closing Notice",
    "Commitment Change",
    "Fee Payment",
    "Money Movement-Inbound",
    "Money Movement-Outbound"
]

SUB_REQUEST_TYPES = {
    "Closing Notice": ["Reallocation Fees", "Amendment Fees", "Reallocation Principal"],
    "Commitment Change": ["Cashless Roll", "Decrease", "Increase"],
    "Fee Payment": ["Ongoing Fee", "Letter of Credit Fee"],
    "Money Movement-Inbound": ["Principal", "Interest", "Principal + Interest", "Principal+Interest+Fee"],
    "Money Movement-Outbound": ["Timebound", "Foreign Currency"]
}

CONFIGURABLE_FIELDS = {
    "default": ["deal_name", "amount", "expiration_date", "sender_name"],
    "Money Movement-Inbound": ["account_number", "routing_number", "transfer_amount", "currency"],
    "Money Movement-Outbound": ["account_number", "routing_number", "transfer_amount", "currency",
                                "destination_country"],
    "Fee Payment": ["fee_type", "amount", "due_date", "payment_method"],
    "Adjustment": ["adjustment_reason", "amount", "effective_date"]
}


class EmailResponse(BaseModel):
    message_id: str
    sender_email: Optional[str]
    timestamp: str
    subject: str
    summary: str
    request_type: str
    sub_request_type: str
    confidence_score: float
    extracted_fields: Dict
    status: str


class ErrorResponse(BaseModel):
    status: str
    error_message: str


class EmailDuplicateTracker:
    def __init__(self):
        self.message_ids: Set[str] = set()
        self.content_hashes: Dict[str, datetime] = {}
        self.normalized_subjects: Dict[str, datetime] = {}
        self.sender_subject_pairs: Dict[Tuple[str, str], datetime] = {}

    def normalize_subject(self, subject: str) -> str:
        """Normalize subject by removing reply/forward markers and trimming"""
        subject = re.sub(r'^(Fwd:|FW:|Re:|RE:|\[.*?\])+\s*', '', subject, flags=re.IGNORECASE)
        return subject.strip()

    def generate_content_hash(self, content: str) -> str:
        """Generate consistent hash of email content"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def is_duplicate(self, message_id: str, sender: str, subject: str, content: str) -> bool:
        """Check if email is a duplicate using multiple criteria"""
        now = datetime.now(pytz.UTC)
        if message_id in self.message_ids:
            return True
        norm_subject = self.normalize_subject(subject)
        content_hash = self.generate_content_hash(content)
        if content_hash in self.content_hashes:
            if now - self.content_hashes[content_hash] < DUPLICATE_WINDOW:
                return True
        if norm_subject in self.normalized_subjects:
            if now - self.normalized_subjects[norm_subject] < DUPLICATE_WINDOW:
                return True
        sender_subject_key = (sender, norm_subject)
        if sender_subject_key in self.sender_subject_pairs:
            if now - self.sender_subject_pairs[sender_subject_key] < DUPLICATE_WINDOW:
                return True
        self.message_ids.add(message_id)
        self.content_hashes[content_hash] = now
        self.normalized_subjects[norm_subject] = now
        self.sender_subject_pairs[sender_subject_key] = now

        return False

    def cleanup(self):
        """Remove old entries from tracking"""
        now = datetime.now(pytz.UTC)
        old_hashes = [h for h, t in self.content_hashes.items() if now - t > DUPLICATE_WINDOW]
        for h in old_hashes:
            del self.content_hashes[h]
        old_subjects = [s for s, t in self.normalized_subjects.items() if now - t > DUPLICATE_WINDOW]
        for s in old_subjects:
            del self.normalized_subjects[s]
        old_pairs = [p for p, t in self.sender_subject_pairs.items() if now - t > DUPLICATE_WINDOW]
        for p in old_pairs:
            del self.sender_subject_pairs[p]


class EmailProcessor:
    def __init__(self):
        self.gemini_model = genai.GenerativeModel('gemini-2.0-flash')
        self.duplicate_tracker = EmailDuplicateTracker()
        self.processed_emails: List[Dict] = []

    def authenticate_gmail(self) -> Credentials:
        creds = None
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES, redirect_uri="http://localhost:8080/"
                )
                creds = flow.run_local_server(port=8080)

            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)
        return creds

    def extract_text_from_pdf(self, attachment_data: bytes) -> str:
        text = ""
        try:
            pdf_reader = PyPDF2.PdfReader(io.BytesIO(attachment_data))
            for page in pdf_reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
        except Exception as e:
            print(f"PyPDF2 extraction failed: {str(e)}")

        if len(text.strip()) < 100:
            try:
                images = convert_from_bytes(attachment_data)
                for img in images:
                    text += pytesseract.image_to_string(img) + "\n"
            except Exception as e:
                print(f"PDF OCR extraction failed: {str(e)}")

        return text.strip()

    def extract_text_from_image(self, attachment_data: bytes) -> str:
        try:
            image = Image.open(io.BytesIO(attachment_data))
            return pytesseract.image_to_string(image)
        except Exception as e:
            print(f"Image OCR extraction failed: {str(e)}")
            return ""

    def process_attachment(self, part: Dict, service, message_id: str) -> str:
        attachment_id = part['body']['attachmentId']
        attachment = service.users().messages().attachments().get(
            userId='me',
            messageId=message_id,
            id=attachment_id
        ).execute()

        attachment_data = base64.urlsafe_b64decode(attachment['data'])

        if part['mimeType'] == 'application/pdf':
            return self.extract_text_from_pdf(attachment_data)
        elif part['mimeType'].startswith('image/'):
            return self.extract_text_from_image(attachment_data)
        elif part['mimeType'] == 'text/plain':
            return attachment_data.decode('utf-8')

        return ""

    def get_email_content(self, message: Dict, service) -> str:
        parts = message['payload']['parts'] if 'parts' in message['payload'] else [message['payload']]
        body = ""
        attachments_text = []

        for part in parts:
            if part['mimeType'] == 'text/plain':
                if 'data' in part['body']:
                    body += base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
            elif part.get('filename') and part['body'].get('attachmentId'):
                attachments_text.append(self.process_attachment(part, service, message['id']))

        attachments_combined = '\n'.join(attachments_text)
        full_content = f"{body}\n{attachments_combined}"
        return full_content[:MAX_CONTENT_LENGTH]

    def classify_request_type(self, content: str) -> Tuple[str, str, float]:
        prompt = f"""
        Analyze this email and classify it. Return JSON with:
        - "request_type": One of {REQUEST_TYPES}
        - "sub_request_type": relevant subtype from {SUB_REQUEST_TYPES} or ""
        - "confidence": 0-1
        
        Email:
        {content[:10000]}
        """

        try:
            response = self.gemini_model.generate_content(prompt)
            json_str = response.text.strip().replace('```json', '').replace('```', '').strip()
            result = json.loads(json_str)

            request_type = str(result.get('request_type', '')).strip()
            sub_type = str(result.get('sub_request_type', '')).strip()

            matched_request = None
            for rt in REQUEST_TYPES:
                if rt.lower() == request_type.lower():
                    matched_request = rt
                    break

            if not matched_request:
                for rt in REQUEST_TYPES:
                    if rt.lower() in request_type.lower() or request_type.lower() in rt.lower():
                        matched_request = rt
                        break

            if not matched_request:
                raise ValueError(f"Invalid request type: {request_type}")

            matched_subtype = ""
            if sub_type and matched_request in SUB_REQUEST_TYPES:
                for st in SUB_REQUEST_TYPES[matched_request]:
                    if st.lower() == sub_type.lower():
                        matched_subtype = st
                        break

                if not matched_subtype:
                    for st in SUB_REQUEST_TYPES[matched_request]:
                        if (st.lower() in sub_type.lower() or
                                sub_type.lower() in st.lower() or
                                any(word in content.lower() for word in st.lower().split())):
                            matched_subtype = st
                            break

            return (
                matched_request,
                matched_subtype,
                float(result.get('confidence', 0.8))
            )
        except Exception as e:
            print(f"Classification error: {str(e)}")
            return self.fallback_classification(content)

    def fallback_classification(self, content: str) -> Tuple[str, str, float]:
        content_lower = content.lower()
        request_scores = []

        for rt in REQUEST_TYPES:
            score = sum(1 for word in rt.lower().split() if word in content_lower)
            request_scores.append((rt, score))

        primary_type, primary_score = max(request_scores, key=lambda x: x[1])
        confidence = min(primary_score / 3, 1.0)

        subtype = ""
        if primary_type in SUB_REQUEST_TYPES:
            subtype_scores = []
            for st in SUB_REQUEST_TYPES[primary_type]:
                if st.lower() in content_lower:
                    subtype_scores.append((st, 2))
                else:
                    word_score = sum(1 for word in st.lower().split() if word in content_lower)
                    subtype_scores.append((st, word_score))

            if subtype_scores:
                best_subtype, best_score = max(subtype_scores, key=lambda x: x[1])
                if best_score > 0:
                    subtype = best_subtype

        return primary_type, subtype, confidence

    def extract_fields(self, content: str, request_type: str) -> Dict:
        fields_to_extract = CONFIGURABLE_FIELDS.get(request_type, CONFIGURABLE_FIELDS['default'])

        prompt = f"""
        Extract these fields from the email as JSON:
        {fields_to_extract}
        
        Rules:
        - Return null for missing fields
        - Format dates as YYYY-MM-DD
        - Preserve currency symbols
        
        Email:
        {content[:10000]}
        """

        try:
            response = self.gemini_model.generate_content(prompt)
            json_str = response.text.strip().replace('```json', '').replace('```', '').strip()
            extracted = json.loads(json_str)

            for field in fields_to_extract:
                if field not in extracted:
                    extracted[field] = None

            return extracted
        except Exception as e:
            print(f"Extraction error: {str(e)}")
            return self.fallback_extraction(content, fields_to_extract)

    def fallback_extraction(self, content: str, fields_to_extract: List[str]) -> Dict:
        extracted = {}

        if 'amount' in fields_to_extract:
            amounts = re.findall(r'\$\d+(?:,\d+)*(?:\.\d+)?|\d+(?:,\d+)*(?:\.\d+)?\s?(?:USD|EUR|GBP)', content)
            extracted['amount'] = amounts[0] if amounts else None

        date_fields = [f for f in fields_to_extract if 'date' in f.lower()]
        for field in date_fields:
            dates = re.findall(r'\d{4}-\d{2}-\d{2}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4}', content)
            extracted[field] = dates[0] if dates else None

        for field in fields_to_extract:
            if field not in extracted:
                match = re.search(fr'{field.replace("_", "[-_ ]?")}[:=]\s*([^\n]+)', content, re.IGNORECASE)
                extracted[field] = match.group(1).strip() if match else None

        return extracted

    def get_sender_email(self, message: Dict) -> Optional[str]:
        headers = message['payload']['headers']
        for header in headers:
            if header['name'].lower() == 'from':
                from_header = header['value']
                match = re.search(r'<(.+?)>', from_header)
                if match:
                    return match.group(1)
                elif '@' in from_header:
                    return from_header
        return None

    def generate_email_summary(self, content: str, subject: str = "") -> str:
        prompt = f"""
        Generate a concise summary (1-2 sentences) of this email that includes:
        - The main purpose or request
        - Key details like amounts, dates, or important names
        - Any critical action items
        
        Subject: {subject}
        Content: {content[:20000]}
        """

        try:
            response = self.gemini_model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            print(f"Summary generation error: {str(e)}")
            return f"Summary unavailable. Content: {content[:200]}..."

    def get_email_subject(self, message: Dict) -> str:
        headers = message['payload']['headers']
        for header in headers:
            if header['name'].lower() == 'subject':
                return header['value']
        return "No Subject"

    def process_emails(self) -> List[Dict]:
        try:
            creds = self.authenticate_gmail()
            service = build('gmail', 'v1', credentials=creds)
            self.duplicate_tracker.cleanup()
            results = service.users().messages().list(
                userId='me',
                labelIds=['INBOX', 'UNREAD'],
                q="is:unread"
            ).execute()
            messages = results.get('messages', [])
            new_emails = []
            for msg in messages:
                message_id = msg['id']
                try:
                    message = service.users().messages().get(
                        userId='me',
                        id=message_id,
                        format='full'
                    ).execute()
                    subject = self.get_email_subject(message)
                    sender_email = self.get_sender_email(message) or "unknown"
                    full_content = self.get_email_content(message, service)

                    if self.duplicate_tracker.is_duplicate(
                            message_id=message_id,
                            sender=sender_email,
                            subject=subject,
                            content=full_content
                    ):
                        print(f"Skipping duplicate email: {subject}")
                        service.users().messages().modify(
                            userId='me',
                            id=message_id,
                            body={'removeLabelIds': ['UNREAD']}
                        ).execute()
                        continue

                    service.users().messages().modify(
                        userId='me',
                        id=message_id,
                        body={'removeLabelIds': ['UNREAD']}
                    ).execute()

                    request_type, sub_type, confidence = self.classify_request_type(full_content)
                    extracted_fields = self.extract_fields(full_content, request_type)
                    summary = self.generate_email_summary(full_content, subject)

                    result = {
                        "message_id": message_id,
                        "sender_email": sender_email,
                        "timestamp": datetime.fromtimestamp(int(message['internalDate']) / 1000, pytz.UTC).isoformat(),
                        "subject": subject,
                        "summary": summary,
                        "request_type": request_type,
                        "sub_request_type": sub_type,
                        "confidence_score": confidence,
                        "extracted_fields": extracted_fields,
                        "status": "processed"
                    }

                    new_emails.append(result)
                    self.processed_emails.append(result)

                except Exception as e:
                    print(f"Error processing email {message_id}: {str(e)}")
                    new_emails.append({
                        "message_id": message_id,
                        "status": "error",
                        "error_message": str(e)
                    })

            if new_emails:
                processed_count = len([e for e in new_emails if e['status'] == 'processed'])
                print(f"\nProcessed {processed_count} new emails")
                for email in new_emails:
                    if email['status'] == 'processed':
                        print(f"- {email['subject']} ({email['request_type']})")
                print(json.dumps(new_emails, indent=2))

            return new_emails

        except Exception as e:
            print(f"Error in email processing: {str(e)}")
            return []


class EmailMonitor:
    def __init__(self, processor: EmailProcessor, poll_interval: int = POLL_INTERVAL):
        self.processor = processor
        self.poll_interval = poll_interval
        self._running = False

    def start(self):
        self._running = True
        while self._running:
            try:
                new_results = self.processor.process_emails()
                if new_results:
                    print("\nNew emails processed:")
                    for email in new_results:
                        if email['status'] == 'processed':
                            print(f"- {email['subject']} ({email['request_type']})")
            except Exception as e:
                print(f"Monitoring error: {str(e)}")
            time.sleep(self.poll_interval)

    def stop(self):
        self._running = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events"""
    # Startup code
    print("Starting up...")
    genai.configure(api_key=GEMINI_API_KEY)
    monitor_thread = threading.Thread(target=email_monitor.start, daemon=True)
    monitor_thread.start()
    yield
    # Shutdown code
    print("Shutting down...")
    email_monitor.stop()


# Update FastAPI initialization
app = FastAPI(lifespan=lifespan)
email_processor = EmailProcessor()
email_monitor = EmailMonitor(email_processor)


@app.get("/emails", response_model=List[EmailResponse])
async def get_emails():
    return email_processor.processed_emails


@app.get("/emails/{message_id}", response_model=EmailResponse)
async def get_email(message_id: str):
    for email in email_processor.processed_emails:
        if email.get('message_id') == message_id:
            return email
    raise HTTPException(status_code=404, detail="Email not found")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
