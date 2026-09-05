# Google Docs Export - Setup Guide

This guide enables exporting GTM strategy documents directly to Google Docs from the CrewAI workflow.

## Quick Start

```bash
# 1. Run the interactive setup wizard
python setup_google_docs.py

# 2. Follow the prompts to configure credentials and document ID

# 3. Export to Google Docs (automatic on workflow completion)
uv run python src/gtm_project/main.py --domain fintech --mode crewai
```

## Step-by-Step Setup

### Step 1: Create Google Cloud Service Account

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project or select an existing one
3. Enable APIs:
   - Go to **APIs & Services** > **Library**
   - Search for and enable:
     - **Google Docs API**
     - **Google Drive API**
4. Create a Service Account:
   - Go to **Credentials** > **Create Credentials** > **Service Account**
   - Name: `GTM-Research-Agent`
   - Click **Create and Continue**
   - Grant role: `Editor` or `Viewer` (at minimum)
   - Click **Continue** then **Done**

### Step 2: Generate Service Account Credentials

1. Go to **Service Accounts** in your Google Cloud project
2. Click the service account you just created
3. Go to the **Keys** tab
4. Click **Add Key** > **Create new key**
5. Choose **JSON**
6. A `credentials.json` file will download
7. Move it to the project directory:
   ```bash
   mv ~/Downloads/credentials.json ./
   ```

### Step 3: Create a Google Doc

1. Go to [Google Drive](https://drive.google.com)
2. Click **New** > **Google Docs**
3. Name it: `GTM Strategy Memo - [Your Domain]`
4. Share the document with your service account:
   - Click **Share**
   - Copy-paste the service account email (from credentials.json: `client_email`)
   - Grant **Editor** access
   - Click **Share**

### Step 4: Get the Document ID

The document ID is in the URL:
```
https://docs.google.com/document/d/[DOCUMENT_ID]/edit
```

Copy the `[DOCUMENT_ID]` part (it's a long alphanumeric string).

### Step 5: Configure Environment Variables

Add to your `.env` file:

```env
GOOGLE_APPLICATION_CREDENTIALS=./credentials.json
GOOGLE_DOC_ID=<paste-your-document-id-here>
```

### Step 6: Test the Setup

Run the validation command:

```bash
python setup_google_docs.py validate
```

You should see:
```
✅ Valid credentials file: credentials.json
   Service Account: gtm-research-agent@your-project.iam.gserviceaccount.com
✅ Google Doc ID configured: 1A2B3C4D5E6F...
✅ Successfully authenticated with Google Docs API
   Document Title: GTM Strategy Memo - fintech
```

## Usage

### Via Command Line

Export to Google Docs after running the workflow:

```bash
# Run workflow and export to Google Docs
uv run python src/gtm_project/main.py --domain fintech --mode crewai --export-docs
```

### Via Streamlit Chatbot

1. Run the chatbot:
   ```bash
   python -m streamlit run src/gtm_project/chatbot.py
   ```

2. After entering a market or domain, you'll see an **"Export to Google Docs"** button

3. Click it to append the strategy to your Google Doc

4. The button will show a link to your document

### Programmatically

```python
from gtm_project.exporters import export_to_google_docs

strategy_text = "## GTM Strategy\n\n..."
result = export_to_google_docs(strategy_text)

if result.get("status") == "exported":
    print(f"✅ Exported to: {result.get('document_id')}")
else:
    print(f"Error: {result.get('detail')}")
```

## File Structure

After export, you'll have:

```
outputs/
├── gtm_strategy_memo.md              # Markdown version
├── gtm_run_artifact.json             # Full workflow output
├── gtm_strategy_memo.pdf             # PDF version
└── google_docs_payload.json          # Payload sent to Google Docs
```

Plus the strategy appended to your Google Doc in the cloud.

## Troubleshooting

### "File not found: credentials.json"
- Ensure credentials.json is in the project root or specify the full path in `.env`
- Example: `GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json`

### "403 Forbidden" or Permission Error
- Verify the service account email is shared with the Google Doc (with Editor access)
- Check that the document ID is correct (copy from URL again)
- Ensure Google Docs API and Google Drive API are enabled in the project

### "Invalid value for GOOGLE_DOC_ID"
- Copy the document ID directly from the URL, not the full URL
- Format should be: `1A2B3C4D5E6F7G8H9I0J` (alphanumeric string)
- No spaces or special characters

### Dependencies Missing
If you get import errors for `google.oauth2` or `googleapiclient`:

```bash
uv pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client
```

Or update pyproject.toml to include them in dependencies.

## Security Best Practices

1. **Never commit credentials.json** - Add to `.gitignore`:
   ```
   credentials.json
   .env
   ```

2. **Restrict service account permissions** - Grant only necessary scopes

3. **Rotate keys periodically** - Delete old keys in Google Cloud Console

4. **Use different service accounts** for development and production

5. **Monitor API usage** - Check [Google Cloud Console](https://console.cloud.google.com/billing) for unexpected usage

## Advanced: Batch Export Multiple Documents

```python
from gtm_project.exporters import export_to_google_docs

documents = {
    "fintech": "1A2B3C...",
    "healthtech": "2D3E4F...",
    "proptech": "3G4H5I...",
}

for domain, doc_id in documents.items():
    os.environ["GOOGLE_DOC_ID"] = doc_id
    result = export_to_google_docs(f"# GTM Strategy for {domain}\n...")
    print(f"{domain}: {result['status']}")
```

## Support

For issues with:
- **Google Cloud setup**: [Google Cloud Documentation](https://cloud.google.com/docs)
- **Google Docs API**: [Google Docs API Docs](https://developers.google.com/docs)
- **CrewAI integration**: See [main README](./README.md)

---

**Last Updated**: 2026-08-27
