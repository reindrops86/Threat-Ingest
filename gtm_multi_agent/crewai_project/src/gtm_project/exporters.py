from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def write_outputs(result: dict[str, Any], output_dir: str | Path) -> dict[str, str]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    markdown_path = directory / "gtm_strategy_memo.md"
    json_path = directory / "gtm_run_artifact.json"
    pdf_path = directory / "gtm_strategy_memo.pdf"
    google_payload_path = directory / "google_docs_payload.json"
    markdown = str(result["strategy_document"])
    markdown_path.write_text(markdown, encoding="utf-8")
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    write_pdf(pdf_path, markdown)
    google_payload_path.write_text(json.dumps({"title": "GTM Strategy Memo", "content": markdown}, indent=2), encoding="utf-8")
    return {"markdown": str(markdown_path), "json": str(json_path), "pdf": str(pdf_path), "google_docs_payload": str(google_payload_path)}


def write_pdf(path: str | Path, markdown: str) -> None:
    """Write a minimal standards-compliant PDF without external runtime dependencies."""
    lines = [line.encode("latin-1", "replace").decode("latin-1")[:110] for line in markdown.splitlines() if line.strip()]
    pages = [lines[index:index + 48] for index in range(0, len(lines), 48)] or [["GTM Strategy Memo"]]
    objects: list[bytes] = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [] /Count 0 >>", b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    page_refs: list[int] = []
    for page_lines in pages:
        content = "BT /F1 10 Tf 50 750 Td " + " ".join(f"({line.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')}) Tj 0 -14 Td" for line in page_lines) + " ET"
        content_ref = len(objects) + 2
        page_ref = len(objects) + 1
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_ref} 0 R >>".encode("latin-1"))
        objects.append(f"<< /Length {len(content.encode('latin-1'))} >>\nstream\n{content}\nendstream".encode("latin-1"))
        page_refs.append(page_ref)
    objects[1] = f"<< /Type /Pages /Kids [{' '.join(f'{ref} 0 R' for ref in page_refs)}] /Count {len(page_refs)} >>".encode("latin-1")
    body = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(body))
        body.extend(f"{index} 0 obj\n".encode("ascii"))
        body.extend(obj)
        body.extend(b"\nendobj\n")
    xref = len(body)
    body.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    body.extend(b"".join(f"{offset:010d} 00000 n \n".encode("ascii") for offset in offsets[1:]))
    body.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    Path(path).write_bytes(body)


def export_to_google_docs(markdown: str) -> dict[str, str]:
    """Append the memo to an existing Google Doc using file-based or ADC-based auth."""
    document_id = os.getenv("GOOGLE_DOC_ID")
    if not document_id:
        return {"status": "not_configured", "detail": "Set GOOGLE_DOC_ID to enable live export."}

    credentials_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    try:
        from googleapiclient.discovery import build

        if credentials_path:
            from google.oauth2.service_account import Credentials
            credentials = Credentials.from_service_account_file(
                credentials_path,
                scopes=["https://www.googleapis.com/auth/documents"],
            )
        else:
            import google.auth
            credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/documents"])

        service = build("docs", "v1", credentials=credentials)
        service.documents().batchUpdate(
            documentId=document_id,
            body={"requests": [{"insertText": {"endOfSegmentLocation": {}, "text": "\n" + markdown}}]},
        ).execute()
        return {"status": "exported", "document_id": document_id}
    except Exception as exc:
        return {
            "status": "error",
            "detail": f"Google Docs export failed: {exc}",
            "document_id": document_id,
        }