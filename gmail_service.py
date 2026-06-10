import base64
import os
from email.message import EmailMessage

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
TOKEN_FILE = "token.json"
CREDS_FILE = "credentials.json"

# Cache service so OAuth isn't triggered repeatedly
_service = None


def _gmail_service():
    global _service
    if _service is not None:
        return _service

    creds = None

    # Load token if already created
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    # If token missing/expired → refresh or re-auth
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(CREDS_FILE):
                raise FileNotFoundError(f"{CREDS_FILE} not found. Put it beside app.py")
            flow = InstalledAppFlow.from_client_secrets_file(CREDS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)

        # Save token.json for next runs
        with open(TOKEN_FILE, "w", encoding="utf-8") as f:
            f.write(creds.to_json())

    _service = build("gmail", "v1", credentials=creds)
    return _service


def send_gmail_api(to_email: str, subject: str, html_body: str, from_name: str = "Phishing Awareness"):
    service = _gmail_service()

    msg = EmailMessage()
    msg["To"] = to_email
    msg["Subject"] = subject

    # This sets the display name (the real from address is your authorized Gmail)
    msg["From"] = f"{from_name} <me>"

    msg.set_content("Open this email in an HTML-capable client.")
    msg.add_alternative(html_body, subtype="html")

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")

    try:
        return service.users().messages().send(userId="me", body={"raw": raw}).execute()
    except Exception as e:
        # This will show real reason in Flask console
        raise RuntimeError(f"Gmail API send failed: {e}")
