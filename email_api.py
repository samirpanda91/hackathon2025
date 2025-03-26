import os
import base64
import json
import pickle
import re
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import pytz
import google.generativeai as genai
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from PIL import Image
import pytesseract
import PyPDF2
import io
from pdf2image import convert_from_bytes

# Configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
MAX_CONTENT_LENGTH = 30000  # Max characters to process from email content

# Initialize Gemini
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-2.0-flash')

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

# Configurable fields to extract
CONFIGURABLE_FIELDS = {
    "default": ["deal_name", "amount", "expiration_date", "sender_name"],
    "Money Movement-Inbound": ["account_number", "routing_number", "transfer_amount", "currency"],
    "Money Movement-Outbound": ["account_number", "routing_number", "transfer_amount", "currency", "destination_country"],
    "Fee Payment": ["fee_type", "amount", "due_date", "payment_method"],
    "Adjustment": ["adjustment_reason", "amount", "effective_date"]
}

def normalize_text(text):
    """Normalize text by removing special characters and converting to lowercase."""
    if not text or not isinstance(text, str):
        return ""
    # Convert to lowercase and remove special characters
    text = text.lower().strip()
    # Remove all non-alphanumeric characters except spaces
    text = re.sub(r'[^a-z0-9\s]', '', text)
    # Collapse multiple spaces
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def authenticate_gmail():
    """Authenticate with Gmail API."""
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

def extract_text_from_pdf(attachment_data):
    """Extract text from PDF attachment using both PyPDF2 and OCR for scanned PDFs."""
    text = ""
    
    # First try PyPDF2 for text-based PDFs
    try:
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(attachment_data))
        for page in pdf_reader.pages:
            page_text = page.extract_text()
            if page_text:  # Only use if we got text
                text += page_text + "\n"
    except Exception as e:
        print(f"PyPDF2 extraction failed: {str(e)}")
    
    # If we didn't get much text, try OCR with pdf2image
    if len(text.strip()) < 100:
        try:
            images = convert_from_bytes(attachment_data)
            for img in images:
                text += pytesseract.image_to_string(img) + "\n"
        except Exception as e:
            print(f"PDF OCR extraction failed: {str(e)}")
    
    return text.strip()

def extract_text_from_image(attachment_data):
    """Extract text from image using OCR."""
    try:
        image = Image.open(io.BytesIO(attachment_data))
        return pytesseract.image_to_string(image)
    except Exception as e:
        print(f"Image OCR extraction failed: {str(e)}")
        return ""

def process_attachment(part, service, message_id):
    """Process email attachment and return extracted text."""
    attachment_id = part['body']['attachmentId']
    attachment = service.users().messages().attachments().get(
        userId='me',
        messageId=message_id,
        id=attachment_id
    ).execute()
    
    attachment_data = base64.urlsafe_b64decode(attachment['data'])
    
    if part['mimeType'] == 'application/pdf':
        return extract_text_from_pdf(attachment_data)
    elif part['mimeType'].startswith('image/'):
        return extract_text_from_image(attachment_data)
    elif part['mimeType'] == 'text/plain':
        return attachment_data.decode('utf-8')
    
    return ""

def get_email_content(message, service):
    """Extract email body and process attachments."""
    parts = message['payload']['parts'] if 'parts' in message['payload'] else [message['payload']]
    body = ""
    attachments_text = []
    
    for part in parts:
        if part['mimeType'] == 'text/plain':
            if 'data' in part['body']:
                body += base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
        elif part.get('filename') and part['body'].get('attachmentId'):
            attachments_text.append(process_attachment(part, service, message['id']))
    
    attachments_combined = '\n'.join(attachments_text)
    full_content = f"{body}\n{attachments_combined}"
    return full_content[:MAX_CONTENT_LENGTH]

def classify_request_type(content: str) -> Tuple[str, str, float]:
    """Classify email content into request type and subtype using Gemini."""
    prompt = f"""
    Analyze this email and classify it. Return JSON with:
    - "request_type": One of {REQUEST_TYPES}
    - "sub_request_type": relevant subtype from {SUB_REQUEST_TYPES} or ""
    - "confidence": 0-1
    
    Important: When choosing sub_request_type, look for these specific phrases in the email:
    {SUB_REQUEST_TYPES}
    
    Email:
    {content[:10000]}
    """
    
    try:
        response = model.generate_content(prompt)
        json_str = response.text.strip().replace('```json', '').replace('```', '').strip()
        result = json.loads(json_str)
        
        # Get the raw values from the response
        request_type = str(result.get('request_type', '')).strip()
        sub_type = str(result.get('sub_request_type', '')).strip()
        
        # Find matching request type (flexible matching)
        matched_request = None
        for rt in REQUEST_TYPES:
            if rt.lower() == request_type.lower():
                matched_request = rt
                break
        
        if not matched_request:
            # Try partial match if exact match fails
            for rt in REQUEST_TYPES:
                if rt.lower() in request_type.lower() or request_type.lower() in rt.lower():
                    matched_request = rt
                    break
        
        if not matched_request:
            raise ValueError(f"Invalid request type: {request_type}. Valid types are: {REQUEST_TYPES}")
        
        # Enhanced subtype matching
        matched_subtype = ""
        if sub_type and matched_request in SUB_REQUEST_TYPES:
            # First try exact match
            for st in SUB_REQUEST_TYPES[matched_request]:
                if st.lower() == sub_type.lower():
                    matched_subtype = st
                    break
            
            # If no exact match, try partial match
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
        return fallback_classification(content)

def fallback_classification(content: str) -> Tuple[str, str, float]:
    """Fallback classification using keyword matching."""
    content_lower = content.lower()
    
    # Score each request type based on keyword matches
    request_scores = []
    for rt in REQUEST_TYPES:
        score = sum(
            1 for word in rt.lower().split() 
            if word in content_lower
        )
        request_scores.append((rt, score))
    
    # Get the request type with highest score
    primary_type, primary_score = max(request_scores, key=lambda x: x[1])
    confidence = min(primary_score / 3, 1.0)
    
    # Enhanced subtype detection
    subtype = ""
    if primary_type in SUB_REQUEST_TYPES:
        subtype_scores = []
        for st in SUB_REQUEST_TYPES[primary_type]:
            # Check for exact phrase match first
            if st.lower() in content_lower:
                subtype_scores.append((st, 2))  # Higher score for exact match
            else:
                # Check for individual word matches
                word_score = sum(
                    1 for word in st.lower().split() 
                    if word in content_lower
                )
                subtype_scores.append((st, word_score))
        
        if subtype_scores:
            best_subtype, best_score = max(subtype_scores, key=lambda x: x[1])
            if best_score > 0:  # Only use if we found at least one matching word
                subtype = best_subtype
    
    return primary_type, subtype, confidence

def extract_fields(content: str, request_type: str) -> Dict:
    """Extract configurable fields based on request type."""
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
        response = model.generate_content(prompt)
        json_str = response.text.strip().replace('```json', '').replace('```', '').strip()
        extracted = json.loads(json_str)
        
        for field in fields_to_extract:
            if field not in extracted:
                extracted[field] = None
        
        return extracted
    except Exception as e:
        print(f"Extraction error: {str(e)}")
        return fallback_extraction(content, fields_to_extract)

def fallback_extraction(content: str, fields_to_extract: List[str]) -> Dict:
    """Fallback field extraction using regex."""
    extracted = {}
    
    # Amount extraction
    if 'amount' in fields_to_extract:
        amounts = re.findall(r'\$\d+(?:,\d+)*(?:\.\d+)?|\d+(?:,\d+)*(?:\.\d+)?\s?(?:USD|EUR|GBP)', content)
        extracted['amount'] = amounts[0] if amounts else None
    
    # Date extraction
    date_fields = [f for f in fields_to_extract if 'date' in f.lower()]
    for field in date_fields:
        dates = re.findall(r'\d{4}-\d{2}-\d{2}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4}', content)
        extracted[field] = dates[0] if dates else None
    
    # Other fields
    for field in fields_to_extract:
        if field not in extracted:
            match = re.search(fr'{field.replace("_", "[-_ ]?")}[:=]\s*([^\n]+)', content, re.IGNORECASE)
            extracted[field] = match.group(1).strip() if match else None
    
    return extracted

def get_sender_email(message):
    """Extract sender's email address from message headers."""
    headers = message['payload']['headers']
    for header in headers:
        if header['name'].lower() == 'from':
            # Extract email from "Name <email@domain.com>" format
            from_header = header['value']
            match = re.search(r'<(.+?)>', from_header)
            if match:
                return match.group(1)
            # If no angle brackets, return the whole value if it's an email
            elif '@' in from_header:
                return from_header
    return None

def generate_email_summary(content: str, subject: str = "") -> str:
    """Generate a concise summary of the email content using Gemini."""
    prompt = f"""
    Generate a concise summary (2-3 sentences) of this email that includes:
    - The main purpose or request
    - Key details like amounts, dates, or important names
    - Any critical action items
    
    Subject: {subject}
    Content: {content[:20000]}  # Truncate very long content
    
    Return just the summary text, no formatting or labels.
    """
    
    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        print(f"Summary generation error: {str(e)}")
        # Fallback: return first 200 characters of content
        return f"Summary unavailable. Content: {content[:200]}..."

def get_email_subject(message):
    """Extract email subject from message headers."""
    headers = message['payload']['headers']
    for header in headers:
        if header['name'].lower() == 'subject':
            return header['value']
    return "No Subject"

def process_emails():
    """Main function to process unread emails."""
    creds = authenticate_gmail()
    service = build('gmail', 'v1', credentials=creds)
    results = service.users().messages().list(userId='me', labelIds=['INBOX', 'UNREAD']).execute()
    messages = results.get('messages', [])
    
    processed_emails = []
    output = []
    
    for msg in messages:
        try:
            message = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            service.users().messages().modify(userId='me', id=msg['id'], body={'removeLabelIds': ['UNREAD']}).execute()
            
            subject = get_email_subject(message)
            full_content = get_email_content(message, service)
            request_type, sub_type, confidence = classify_request_type(full_content)
            extracted_fields = extract_fields(full_content, request_type)
            sender_email = get_sender_email(message)
            summary = generate_email_summary(full_content, subject)
            
            result = {
                "sender_email": sender_email,
                "timestamp": datetime.fromtimestamp(int(message['internalDate'])/1000, pytz.UTC).isoformat(),
                "subject": subject,
                "summary": summary,
                "request_type": request_type,
                "sub_request_type": sub_type,
                "confidence_score": confidence,
                "extracted_fields": extracted_fields,
                "status": "processed"
            }
            
            output.append(result)
            processed_emails.append({
                "content": full_content,
                "request_type": request_type
            })
            
        except Exception as e:
            print(f"Error processing email {msg.get('id', 'unknown')}: {str(e)}")
            output.append({
                "status": "error",
                "error_message": str(e)
            })
    
    return output

if __name__ == "__main__":
    results = process_emails()
    print(json.dumps(results, indent=2))
