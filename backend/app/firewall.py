import base64
import binascii
import codecs
import html
import re
import unicodedata
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import unquote


RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "Instruction override",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b.{0,60}\b"
            r"(previous|prior|above|system|developer)\b.{0,30}\b"
            r"(instructions?|rules?|messages?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "Role change",
        re.compile(
            r"\b(you are now|act as|pretend to be|switch to|roleplay as)\b"
            r".{0,50}\b(system|developer|admin|administrator|assistant)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "Secret extraction",
        re.compile(
            r"\b(reveal|print|show|dump|exfiltrate|leak|send)\b.{0,60}\b"
            r"(system prompt|api key|secret|credentials?|password|access token)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "Tool abuse",
        re.compile(
            r"\b(send|forward|delete|upload|execute|run|call|open)\b.{0,60}\b"
            r"(email|file|url|command|tool|shell|browser|http request)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "Credential theft",
        re.compile(
            r"\b(api key|password|access token|credentials?)\b.{0,50}\b"
            r"(send|sends|sending|sent|share|shares|sharing|reveal|exfiltrate|paste|provide|email)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
)

ENCODED_RUN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/])")
HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{24,}(?![0-9A-Fa-f])")
ZERO_WIDTH = re.compile("[\u200b-\u200f\u2060\ufeff]")


def _clean_unicode(value: str) -> str:
    return unicodedata.normalize("NFKC", ZERO_WIDTH.sub("", value))


def _looks_like_text(value: str) -> bool:
    return bool(value) and sum(character.isprintable() or character.isspace() for character in value) / len(value) > 0.85


def _decoded_candidates(text: str, source: str) -> list[tuple[str, str]]:
    candidates = [(source, text)]
    cleaned = _clean_unicode(text)
    if cleaned != text:
        candidates.append((f"{source}:unicode_normalized", cleaned))

    url_decoded = unquote(html.unescape(cleaned))
    if url_decoded != cleaned:
        candidates.append((f"{source}:url_decoded", url_decoded))

    for match in ENCODED_RUN.finditer(cleaned):
        try:
            decoded = base64.b64decode(match.group(), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _looks_like_text(decoded):
            candidates.append((f"{source}:base64_decoded", decoded))

    for match in HEX_RUN.finditer(cleaned):
        try:
            decoded = bytes.fromhex(match.group()).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            continue
        if _looks_like_text(decoded):
            candidates.append((f"{source}:hex_decoded", decoded))

    rot13 = codecs.decode(cleaned, "rot_13")
    if rot13 != cleaned and any(pattern.search(rot13) for _, pattern in RULES):
        candidates.append((f"{source}:rot13_decoded", rot13))

    return candidates


class _HTMLSegments(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible: list[str] = []
        self.hidden: list[str] = []
        self.comments: list[str] = []
        self.scripts: list[str] = []
        self._hidden_depth = 0
        self._script_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        style = (attributes.get("style") or "").replace(" ", "").lower()
        is_hidden = (
            "hidden" in attributes
            or (attributes.get("aria-hidden") or "").lower() == "true"
            or "display:none" in style
            or "visibility:hidden" in style
        )
        if is_hidden:
            self._hidden_depth += 1
        if tag.lower() == "script":
            self._script_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._script_depth:
            self._script_depth -= 1
        if self._hidden_depth and tag.lower() not in {"meta", "link", "img", "br", "hr", "input"}:
            self._hidden_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._script_depth:
            self.scripts.append(data)
        elif self._hidden_depth:
            self.hidden.append(data)
        else:
            self.visible.append(data)

    def handle_comment(self, data: str) -> None:
        self.comments.append(data)


def extract_segments(content: str, input_format: str) -> list[dict[str, str]]:
    normalized_format = input_format.lower()
    if normalized_format == "html":
        parser = _HTMLSegments()
        parser.feed(content)
        segments = [{"source": "html_visible_text", "text": " ".join(parser.visible)}]
        segments.extend({"source": "html_comment", "text": item} for item in parser.comments)
        segments.extend({"source": "hidden_html", "text": item} for item in parser.hidden)
        segments.extend({"source": "script_content", "text": item} for item in parser.scripts)
        return [segment for segment in segments if segment["text"].strip()]

    if normalized_format == "email":
        message = BytesParser(policy=policy.default).parsebytes(content.encode("utf-8", errors="replace"))
        segments = []
        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() not in {"text/plain", "text/html"}:
                continue
            body = part.get_content()
            body_text = body if isinstance(body, str) else str(body)
            if part.get_content_type() == "text/html":
                segments.extend(extract_segments(body_text, "html"))
            elif body_text.strip():
                segments.append({"source": "email_body", "text": body_text})
        return segments or [{"source": "email_body", "text": content}]

    return [{"source": "user_text", "text": content}]


def extract_file_segments(filename: str, content: bytes) -> list[dict[str, str]]:
    extension = Path(filename).suffix.lower()
    if extension == ".pdf":
        from pypdf import PdfReader

        reader = PdfReader(BytesIO(content))
        return [
            {"source": f"pdf_page_{page_number}", "text": page.extract_text() or ""}
            for page_number, page in enumerate(reader.pages, start=1)
            if (page.extract_text() or "").strip()
        ]

    text = content.decode("utf-8", errors="replace")
    if extension in {".html", ".htm"}:
        return extract_segments(text, "html")
    if extension == ".eml":
        return extract_segments(text, "email")
    if extension in {".txt", ".md"}:
        return extract_segments(text, "text")
    raise ValueError("Supported files: PDF, HTML, EML, TXT, and Markdown.")


def _is_quoted_reference(text: str, start: int, end: int) -> bool:
    before = text[:start]
    after = text[end:]
    quoted = bool(re.search(r"[\"'“‘]\s*$", before) and re.match(r"\s*[\"'”’]", after))
    context = text[max(0, start - 120) : min(len(text), end + 120)]
    described_as_example = bool(
        re.search(r"\b(discuss(?:es|ed|ing)?|phrase|example|security|quoted|quotation|article)\b", context, re.I)
    )
    return quoted and described_as_example


def analyze_segments(segments: list[dict[str, str]]) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add_finding(category: str, source: str, evidence: str) -> None:
        key = (category, source, evidence)
        if key not in seen:
            seen.add(key)
            findings.append({"category": category, "source": source, "evidence": evidence[:180]})

    for segment in segments:
        source = segment["source"]
        for candidate_source, candidate_text in _decoded_candidates(segment["text"], source):
            is_hidden = source in {"html_comment", "hidden_html", "script_content"}
            is_decoded = candidate_source != source
            matched = False
            for category, pattern in RULES:
                match = pattern.search(candidate_text)
                if not match:
                    continue
                if category == "Instruction override" and _is_quoted_reference(
                    candidate_text, match.start(), match.end()
                ):
                    continue
                matched = True
                evidence = match.group(0).strip()
                add_finding(category, candidate_source, evidence)
                if is_hidden:
                    add_finding("Indirect prompt injection", candidate_source, evidence)
                if is_decoded:
                    add_finding("Encoded instructions", candidate_source, evidence)
            if matched and is_hidden:
                add_finding("Indirect prompt injection", source, "Instruction-like content was found in a non-visible HTML segment.")

    categories = sorted({finding["category"] for finding in findings})
    hidden_or_decoded = any(
        ":" in finding["source"] or finding["source"] in {"html_comment", "hidden_html", "script_content"}
        for finding in findings
    )
    if not findings:
        decision = "PASS"
    elif hidden_or_decoded:
        decision = "QUARANTINE"
    else:
        decision = "BLOCK"

    return {
        "decision": decision,
        "risk_score": min(100, len(categories) * 20),
        "categories": categories,
        "findings": findings,
        "segment_count": len(segments),
    }


def guard_tool_call(user_request: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    request = user_request.casefold()
    target = str(arguments.get("path", "") if tool_name == "read_document" else arguments.get("recipient", ""))
    target_in_request = bool(target) and target.casefold() in request

    if tool_name == "read_document":
        intent = bool(re.search(r"\b(read|open|summari[sz]e|analy[sz]e)\b.{0,50}\b(file|document|report)\b", request))
    elif tool_name == "send_email":
        intent = bool(re.search(r"\bsend\s+(an?\s+)?email\b", request))
        intent = intent and bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", target))
    else:
        return {"allowed": False, "reason": "This tool is not in the demo agent's allowlist."}

    if intent and target_in_request:
        return {"allowed": True, "reason": "The user explicitly requested this tool and named its target."}
    return {
        "allowed": False,
        "reason": "The original user request does not explicitly authorize this action and target.",
    }
