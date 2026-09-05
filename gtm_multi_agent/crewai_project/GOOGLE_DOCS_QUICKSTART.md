# Google Docs Export - Quick Start

## 🚀 Get Started in 5 Minutes

### Step 1: Set Up Credentials (2 minutes)

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project
3. Enable **Google Docs API** and **Google Drive API**
4. Create a Service Account and download credentials.json
5. Move credentials to project root:
   ```bash
   mv ~/Downloads/credentials.json ./
   ```

### Step 2: Create a Google Doc (1 minute)

1. Go to [Google Drive](https://drive.google.com)
2. Create a new Google Doc
3. Share it with your service account email (from credentials.json)
4. Copy the document ID from the URL

### Step 3: Configure (.env) (1 minute)

Run the setup wizard:
```bash
python setup_google_docs.py
```

It will ask for:
- Path to credentials.json (default: `./credentials.json`)
- Google Doc ID

Or manually edit `.env`:
```env
GOOGLE_APPLICATION_CREDENTIALS=./credentials.json
GOOGLE_DOC_ID=YOUR_DOCUMENT_ID_HERE
```

### Step 4: Test (1 minute)

```bash
python test_google_docs.py
```

You should see:
```
✅ All tests passed! Google Docs export is ready.
```

## 📝 Usage

### Via Streamlit Chatbot
```bash
python -m streamlit run src/gtm_project/chatbot.py
```

Then:
1. Enter a domain (e.g., "fintech")
2. Click **"📝 Export to Google Docs"** button
3. Done! Check your Google Doc

### Via Command Line
```bash
uv run python src/gtm_project/main.py --domain fintech --mode crewai --export-docs
```

Output will show:
```
✅ Strategy exported to Google Doc: 1A2B3C4D5E6F...
   Link: https://docs.google.com/document/d/1A2B3C4D5E6F/edit
```

### Programmatically
```python
from gtm_project.exporters import export_to_google_docs

strategy = "## GTM Strategy\n..."
result = export_to_google_docs(strategy)
print(f"✅ Exported: {result['document_id']}")
```

## 🔧 Troubleshooting

| Problem | Fix |
|---------|-----|
| "credentials.json not found" | Copy credentials.json to project root |
| "403 Forbidden" | Share Google Doc with service account email |
| "Invalid document ID" | Copy ID from URL: `docs.google.com/document/d/[ID]/edit` |

Run validation:
```bash
python setup_google_docs.py validate
```

## 📚 Full Docs

See [GOOGLE_DOCS_SETUP.md](./GOOGLE_DOCS_SETUP.md) for complete instructions

## ✅ What You'll Get

After export:
- ✅ GTM strategy in Google Docs
- ✅ Real-time collaboration enabled
- ✅ Easy sharing with team
- ✅ Version history preserved
- ✅ Local files also saved (Markdown, PDF, JSON)

---

**Questions?** Check the troubleshooting section or see detailed docs.
