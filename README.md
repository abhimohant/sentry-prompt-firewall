# Sentry: Prompt-Injection Firewall

A Python-first hackathon prototype with a FastAPI detection service and a Streamlit demo UI. The first slice inspects pasted text and uploaded PDF, HTML, EML, TXT, and Markdown files, reports source-aware findings, and checks proposed tool calls against the original user request.

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Start the API in one terminal:

```powershell
python -m uvicorn backend.app.main:app --reload
```

Start the UI in another terminal:

```powershell
python -m streamlit run frontend/streamlit_app.py
```

Open `http://localhost:8501`. The API health endpoint is `http://localhost:8000/health`.

Run the core tests with:

```powershell
python -m unittest discover -s backend/tests -v
```

Run the starter evaluation set with:

```powershell
python -m backend.evaluate
```

## Current scope

- Rule-based checks for instruction override, role change, secret extraction, tool abuse, credential theft, encoded instructions, and indirect prompt injection.
- URL, Base64, hex, and ROT13 decoding for detection. Findings retain the extraction/decoding source; input is not rewritten.
- HTML comments, hidden elements, and script content are scanned separately from visible text.
- A separate allowlist-based tool guard requires explicit user intent and a named target. It does not execute tools.
- Rules are a baseline, not a security guarantee. Detection metrics and false-positive behavior need evaluation on a frozen labeled dataset before making performance claims.
- `backend/evaluation/cases.json` is a tiny development fixture, not a benchmark. Do not present its metrics as general performance results.
