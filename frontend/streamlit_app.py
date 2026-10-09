import os

import requests
import streamlit as st


API_URL = os.getenv("FIREWALL_API_URL", "http://127.0.0.1:8000")

st.set_page_config(page_title="Sentry | Prompt Firewall", page_icon="S", layout="wide")
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
    :root { --ink:#101512; --paper:#f2f4ee; --acid:#c8f169; --red:#ff654f; --line:#d6dbd2; }
    html, body, [class*="css"] { font-family: 'Manrope', sans-serif; }
    .stApp { background:var(--paper); color:var(--ink); }
    [data-testid="stHeader"] { background:transparent; }
    .block-container { max-width:1240px; padding-top:2.2rem; padding-bottom:4rem; }
    .masthead { display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--line); padding:0 0 1rem; margin-bottom:2.3rem; }
    .brand { font-size:14px; font-weight:800; letter-spacing:0; text-transform:uppercase; }
    .brand span { display:inline-block; width:10px; height:10px; background:var(--acid); border:1px solid var(--ink); margin-right:9px; }
    .status { font:11px 'DM Mono',monospace; color:#47504a; text-transform:uppercase; }
    h1 { font-size:4.2rem; line-height:.98; letter-spacing:0; max-width:800px; margin:0 0 1rem; }
    .lede { color:#5a625c; max-width:650px; font-size:15px; line-height:1.7; margin-bottom:2rem; }
    h2, h3 { letter-spacing:0 !important; }
    [data-testid="stVerticalBlockBorderWrapper"] { border:1px solid var(--line); border-radius:3px; background:#fbfcf8; }
    [data-testid="stFileUploader"] section { background:#fbfcf8; border-color:#aab2a8; border-radius:3px; }
    [data-testid="stTextArea"] textarea, [data-testid="stTextInput"] input, [data-testid="stSelectbox"] div[data-baseweb="select"] { border-radius:3px; }
    .eyebrow { font:11px 'DM Mono',monospace; text-transform:uppercase; color:#5a625c; margin:0 0 8px; }
    .verdict { padding:1.1rem 1.2rem; border:1px solid var(--ink); border-left:8px solid var(--acid); background:#fff; margin:.5rem 0 1rem; }
    .verdict.block, .verdict.quarantine { border-left-color:var(--red); }
    .verdict strong { display:block; font:700 24px 'DM Mono',monospace; margin-bottom:5px; }
    .verdict small { color:#59615b; font:12px 'DM Mono',monospace; }
    .finding { border-top:1px solid var(--line); padding:12px 0; }
    .finding b { font-size:13px; }
    .finding code { display:block; white-space:normal; color:#59615b; background:transparent; font:11px 'DM Mono',monospace; padding:5px 0 0; }
    div.stButton > button { border:1px solid var(--ink); border-radius:3px; background:var(--acid); color:var(--ink); font-weight:800; min-height:44px; }
    div.stButton > button:hover { border-color:var(--ink); background:#b4e253; color:var(--ink); }
    .mono { font-family:'DM Mono',monospace; }
    @media (max-width:700px) { .block-container { padding:1.2rem 1rem 3rem; } .masthead { margin-bottom:1.5rem; } h1 { font-size:2.6rem; } }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="masthead"><div class="brand"><span></span>Sentry / Content Firewall</div>'
    '<div class="status">Local prototype · Rule engine online</div></div>',
    unsafe_allow_html=True,
)
st.markdown("# Untrusted content,\n# under scrutiny.")
st.markdown(
    '<p class="lede">Inspect documents and messages for prompt injection. Findings retain their source; '
    'suspicious hidden or decoded instructions are quarantined, never silently rewritten.</p>',
    unsafe_allow_html=True,
)

analyze_tab, tool_tab = st.tabs(["01 / Content inspection", "02 / Tool-call guard"])

with analyze_tab:
    left, right = st.columns([1.1, 0.9], gap="large")
    with left:
        st.markdown('<p class="eyebrow">Input channel</p>', unsafe_allow_html=True)
        uploaded = st.file_uploader("Drop a file to inspect", type=["pdf", "html", "htm", "eml", "txt", "md"])
        st.caption("PDF · HTML · EML · TXT · Markdown · up to 10 MB")
        input_format = st.selectbox("Or paste content", ["text", "html", "email"], format_func=str.upper)
        content = st.text_area("Content", height=240, placeholder="Paste untrusted content here…")
        inspect = st.button("Inspect content", use_container_width=True)
    with right:
        st.markdown('<p class="eyebrow">Firewall verdict</p>', unsafe_allow_html=True)
        if inspect:
            try:
                if uploaded is not None:
                    response = requests.post(
                        f"{API_URL}/analyze-file",
                        files={"file": (uploaded.name, uploaded.getvalue(), uploaded.type)},
                        timeout=30,
                    )
                elif content.strip():
                    response = requests.post(
                        f"{API_URL}/analyze",
                        json={"content": content, "input_format": input_format},
                        timeout=30,
                    )
                else:
                    st.warning("Add content or choose a file first.")
                    response = None

                if response is not None:
                    response.raise_for_status()
                    st.session_state["analysis_result"] = response.json()
            except requests.RequestException as error:
                st.error(f"Firewall API unavailable: {error}")

        result = st.session_state.get("analysis_result")
        if result:
            decision = result["decision"]
            st.markdown(
                f'<div class="verdict {decision.lower()}"><strong>{decision}</strong>'
                f'<small>RISK {result["risk_score"]:02d} / 100 · {result["segment_count"]} SOURCE SEGMENT(S)</small></div>',
                unsafe_allow_html=True,
            )
            if result["categories"]:
                st.markdown("**Detected categories**")
                for category in result["categories"]:
                    st.write(f"· {category}")
                for finding in result["findings"]:
                    st.markdown(
                        f'<div class="finding"><b>{finding["category"]}</b>'
                        f'<code>{finding["source"]} · {finding["evidence"]}</code></div>',
                        unsafe_allow_html=True,
                    )
            else:
                st.success("No matching attack patterns found in the extracted content.")
            with st.expander("Extracted content and provenance"):
                st.code(result["extracted_text"] or "No text could be extracted.", language="text")
                st.caption("Sources: " + (", ".join(result["sources"]) or "none"))
        else:
            st.info("Submit content to see the decision, evidence, and extraction sources here.")

with tool_tab:
    st.markdown('<p class="eyebrow">Independent authorization check</p>', unsafe_allow_html=True)
    st.write("This guard evaluates the user's request and proposed tool call only. Scanned document text is not an authorization signal.")
    request_text = st.text_area("Original user request", placeholder="Example: Read the file Q3-report.pdf")
    selected_tool = st.selectbox("Proposed tool", ["read_document", "send_email", "delete_file"])
    if selected_tool == "send_email":
        target = st.text_input("Recipient", placeholder="person@example.com")
        arguments = {"recipient": target}
    else:
        target = st.text_input("Target file", placeholder="Q3-report.pdf")
        arguments = {"path": target}
    if st.button("Check proposed action"):
        try:
            response = requests.post(
                f"{API_URL}/tool-guard",
                json={"user_request": request_text, "tool_name": selected_tool, "arguments": arguments},
                timeout=10,
            )
            response.raise_for_status()
            guard_result = response.json()
            if guard_result["allowed"]:
                st.success("ALLOW · " + guard_result["reason"])
            else:
                st.error("DENY · " + guard_result["reason"])
        except requests.RequestException as error:
            st.error(f"Firewall API unavailable: {error}")
