def get_unread_emails():
    creds = authenticate_gmail()
    service = build('gmail', 'v1', credentials=creds)

    # Fetch unread emails in the inbox
    results = service.users().messages().list(userId='me', q="is:unread label:inbox").execute()
    messages = results.get('messages', [])

    unread_count = len(messages)
    print(f"Number of new unread emails in inbox: {unread_count}")

    if not messages:
        print("No new unread emails.")
        return

    for msg in messages:
        msg_id = msg['id']
        email_data = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

        headers = email_data["payload"]["headers"]
        subject = next(header["value"] for header in headers if header["name"] == "Subject")
        sender = next(header["value"] for header in headers if header["name"] == "From")

        print(f"From: {sender}\nSubject: {subject}\n{'-'*50}")

if __name__ == "__main__":
    get_unread_emails()