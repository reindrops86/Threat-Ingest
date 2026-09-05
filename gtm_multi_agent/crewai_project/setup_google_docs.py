#!/usr/bin/env python3
"""
Setup script for Google Docs export integration.

This script guides you through:
1. Creating a Google Cloud service account
2. Getting service account credentials
3. Creating a sample Google Doc
4. Configuring environment variables for auto-export
"""

import json
import os
import sys
from pathlib import Path


def print_header(text: str) -> None:
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70 + "\n")


def check_existing_config() -> dict[str, str]:
    """Check if Google Docs config already exists."""
    env_path = Path(__file__).parent / ".env"
    config = {}
    
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                if line.startswith("GOOGLE_"):
                    key, val = line.strip().split("=", 1)
                    config[key] = val
    
    return config


def print_instructions() -> None:
    """Print setup instructions."""
    print_header("GOOGLE DOCS EXPORT SETUP")
    
    print("""
This setup enables exporting GTM strategy documents directly to Google Docs.

PREREQUISITES:
1. Google Cloud Project (free tier available at cloud.google.com)
2. Google Drive account for storing the strategy document
3. Service account credentials JSON file

STEPS:
""")
    
    print("""
STEP 1: Create a Google Cloud Project
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Go to console.cloud.google.com
2. Create a new project (or select existing one)
3. Enable these APIs:
   - Google Docs API
   - Google Drive API
4. Create a service account:
   - Console > Credentials > Create Credentials > Service Account
   - Name: "GTM-Research-Agent"
   - Grant role: "Editor" or "Viewer" (at minimum)
5. Create a key:
   - Service Account > Keys > Add Key > Create new key > JSON
   - Save as: `credentials.json`


STEP 2: Create a Sample Google Doc
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Go to Google Drive (drive.google.com)
2. Create a new Google Doc (File > New > Google Docs)
3. Name it: "GTM Strategy Memo - [Your Domain]"
4. Click the Share button and add your service account email
   - Email format: <service-account>@<project>.iam.gserviceaccount.com
   - Grant "Editor" access
5. Copy the document ID from the URL:
   - URL: docs.google.com/document/d/[DOCUMENT_ID]/edit
   - Extract: [DOCUMENT_ID]


STEP 3: Configure Environment Variables
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Add to .env file:
  GOOGLE_APPLICATION_CREDENTIALS=./credentials.json
  GOOGLE_DOC_ID=<your-document-id>


STEP 4: Test the Export
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
python src/gtm_project/main.py --domain fintech --mode crewai --export-docs

This will:
1. Run the live CrewAI workflow
2. Generate the GTM strategy
3. Append it to your Google Doc
4. Print confirmation with the document link
    """)


def validate_setup() -> bool:
    """Validate that Google Docs is properly configured."""
    creds_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    doc_id = os.getenv("GOOGLE_DOC_ID")
    
    print_header("VALIDATING SETUP")
    
    if not creds_path:
        print("❌ GOOGLE_APPLICATION_CREDENTIALS not set")
        return False
    
    creds_file = Path(creds_path)
    if not creds_file.exists():
        print(f"❌ Credentials file not found: {creds_file.absolute()}")
        return False
    
    try:
        with open(creds_file) as f:
            creds = json.load(f)
            if "type" not in creds or creds["type"] != "service_account":
                print("❌ Invalid service account credentials format")
                return False
            print(f"✅ Valid credentials file: {creds_file.name}")
            print(f"   Service Account: {creds.get('client_email')}")
    except Exception as e:
        print(f"❌ Error reading credentials: {e}")
        return False
    
    if not doc_id:
        print("❌ GOOGLE_DOC_ID not set")
        return False
    
    print(f"✅ Google Doc ID configured: {doc_id[:20]}...")
    
    # Try to authenticate
    try:
        from google.oauth2.service_account import Credentials
        from googleapiclient.discovery import build
        
        credentials = Credentials.from_service_account_file(
            creds_path,
            scopes=["https://www.googleapis.com/auth/documents"]
        )
        service = build("docs", "v1", credentials=credentials)
        doc = service.documents().get(documentId=doc_id).execute()
        print(f"✅ Successfully authenticated with Google Docs API")
        print(f"   Document Title: {doc.get('title')}")
        return True
    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        print("\nTroubleshooting:")
        print("1. Verify service account email is shared with the Google Doc")
        print("2. Check that credentials file path is correct")
        print("3. Ensure GOOGLE_DOC_ID is copied exactly (including trailing characters)")
        return False


def interactive_setup() -> None:
    """Interactive setup wizard."""
    print_header("GOOGLE DOCS SETUP WIZARD")
    
    print("Do you have:")
    print("1. A Google Cloud service account credentials JSON file? (y/n)")
    has_creds = input("→ ").lower().strip() in ("y", "yes")
    
    if not has_creds:
        print_instructions()
        print("\nRun this script again after completing the setup steps.")
        return
    
    print("\n2. The credentials file path?")
    creds_path = input("→ Enter path (relative or absolute): ").strip()
    
    if not Path(creds_path).exists():
        print(f"❌ File not found: {creds_path}")
        return
    
    print("\n3. A Google Doc ID?")
    doc_id = input("→ Enter document ID (from docs.google.com/document/d/[ID]/edit): ").strip()
    
    # Update .env
    env_path = Path(__file__).parent / ".env"
    env_content = env_path.read_text() if env_path.exists() else ""
    
    # Remove old Google Docs config
    lines = [l for l in env_content.split("\n") if not l.startswith("GOOGLE_")]
    lines.append(f"GOOGLE_APPLICATION_CREDENTIALS={creds_path}")
    lines.append(f"GOOGLE_DOC_ID={doc_id}")
    
    env_path.write_text("\n".join(lines).strip() + "\n")
    print(f"\n✅ Updated .env file: {env_path}")
    
    # Validate
    if validate_setup():
        print_header("SETUP COMPLETE")
        print("""
You can now export GTM strategies directly to Google Docs!

Examples:
  # Run workflow and export to Google Docs
  uv run python src/gtm_project/main.py --domain fintech --mode crewai

  # The strategy will automatically be appended to your Google Doc

To verify:
  1. Open your Google Doc in a browser
  2. Look for the GTM strategy memo appended at the end
  3. Share the doc link with team members
        """)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "validate":
        validate_setup()
    elif len(sys.argv) > 1 and sys.argv[1] == "instructions":
        print_instructions()
    else:
        interactive_setup()
