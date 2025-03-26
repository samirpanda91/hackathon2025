# Email Processing System with Gemini AI Integration

This system processes incoming emails, classifies them by request type, extracts key information, and provides summaries using Google's Gemini AI.

## Features

- Gmail integration for email processing
- AI-powered classification of email requests
- Field extraction from email content
- Duplicate email detection
- PDF and image attachment processing (OCR)
- REST API for accessing processed emails
- Background monitoring of new emails

## Installation
Set up Python environment: (Python 3.9.0)
- python -m venv venv
- source venv/bin/activate  # On Windows: venv\Scripts\activate
Install dependencies:
- pip install -r requirements.txt
Set up Google Cloud credentials:
- Create a project in Google Cloud Console
- Enable the Gmail API
- Create OAuth 2.0 credentials (Desktop app type)
- Download the credentials JSON file and save as credentials.json in the project root
Set environment variables:
- export GEMINI_API_KEY="your-gemini-api-key"

## Configuration
Edit the following variables in main.py as needed:
- SCOPES: Gmail API permissions
- MAX_CONTENT_LENGTH: Maximum email content length to process
- POLL_INTERVAL: How often to check for new emails (seconds)
- DUPLICATE_WINDOW: Time window for duplicate detection
- REQUEST_TYPES and SUB_REQUEST_TYPES: Customize your request classifications
- CONFIGURABLE_FIELDS: Define what fields to extract for each request type

## Usage
Run the application:
- python main.py
First-time setup:
- The first run will open a browser window for Google OAuth authentication
- Approve the permissions to allow access to your Gmail account
- A token.pickle file will be created for future authentications
Access the API:
- The API will be available at http://localhost:8000
Endpoints:
- GET /emails - List all processed emails
- GET /emails/{message_id} - Get details for a specific email
Monitor logs:
- The system will log processed emails to the console
- Processed emails are stored in memory and available via the API

## API Documentation
Endpoints:
- GET /emails - Returns all processed emails
- GET /emails/{message_id} - Returns a specific email by its message ID
