import hashlib
import html
import json
import os
import re
import time
from typing import Optional
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, HttpUrl
from redis import Redis


app = FastAPI(title="URL Analyzer", version="1.0.0")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
SAFE_BROWSING_KEY = os.getenv("SAFE_BROWSING_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
CACHE_SECONDS = int(os.getenv("CACHE_SECONDS", "3600"))
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "30"))
RATE_WINDOW_SECONDS = 60


class AnalyzeRequest(BaseModel):
    url: HttpUrl


def get_redis() -> Optional[Redis]:
    try:
        client = Redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=0.2)
        client.ping()
        return client
    except Exception:
        return None


def cache_key(url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return f"url-analyzer:v7:{digest}"


def local_checks(url: str) -> list[str]:
    parsed = urlparse(url)
    warnings = []
    if parsed.scheme != "https":
        warnings.append("URL does not use HTTPS")
    if "@" in parsed.netloc:
        warnings.append("URL contains an embedded username")
    if len(url) > 200:
        warnings.append("URL is unusually long")
    return warnings


def clean_text(value: str, limit: int = 240) -> str:
    value = html.unescape(re.sub(r"<[^>]+>", " ", value))
    value = re.sub(r"\s+", " ", value).strip()
    value = re.sub(r"[.!?]+", "", value)
    return value[:limit].rstrip(" ,;:")


async def page_details(url: str) -> dict:
    try:
        async with httpx.AsyncClient(
            timeout=3.0,
            follow_redirects=True,
            headers={"User-Agent": "Simple URL Analyzer/1.0"},
        ) as client:
            response = await client.get(url)
        content = response.text[:500000]
        title_match = re.search(r"<title[^>]*>(.*?)</title>", content, re.I | re.S)
        description_match = re.search(
            r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']',
            content,
            re.I | re.S,
        )
        headings = re.findall(r"<h[1-3][^>]*>(.*?)</h[1-3]>", content, re.I | re.S)
        paragraphs = re.findall(r"<p[^>]*>(.*?)</p>", content, re.I | re.S)
        visible_text = re.sub(r"<(script|style|noscript)[^>]*>.*?</\1>", " ", content, flags=re.I | re.S)
        return {
            "title": clean_text(title_match.group(1)) if title_match else "",
            "description": clean_text(description_match.group(1)) if description_match else "",
            "headings": [clean_text(item, 80) for item in headings[:3] if clean_text(item, 80)],
            "paragraphs": [clean_text(item, 350) for item in paragraphs if len(clean_text(item, 350)) > 50][:4],
            "text": clean_text(visible_text, 6000),
        }
    except Exception as exc:
        return {"title": "", "description": "", "headings": [], "paragraphs": [], "text": "", "error": str(exc)}


async def gemini_summary(url: str, details: dict) -> Optional[str]:
    if not GEMINI_API_KEY or not details.get("text"):
        return None
    prompt = (
        "Write exactly three short sentences summarizing this webpage for a safety dashboard. "
        "Describe what the page is about using only the supplied content. Do not mention that you are an AI, "
        "do not assess safety, and do not use bullet points.\n\n"
        f"URL: {url}\nTitle: {details.get('title', '')}\n"
        f"Description: {details.get('description', '')}\nPage text: {details.get('text', '')}"
    )
    endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent"
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.post(
                endpoint,
                headers={"x-goog-api-key": GEMINI_API_KEY},
                json=payload,
            )
        response.raise_for_status()
        candidates = response.json().get("candidates", [])
        parts = candidates[0].get("content", {}).get("parts", []) if candidates else []
        summary = " ".join(part.get("text", "").strip() for part in parts).strip()
        return summary or None
    except Exception:
        return None


def make_summary(url: str, details: dict) -> str:
    host = urlparse(url).netloc
    subject = details.get("title") or host
    description = details.get("description")
    headings = details.get("headings", [])
    paragraphs = details.get("paragraphs", [])
    page_text = details.get("text", "")

    first = f"{subject} is a website at {host}."
    third = "This summary is based on the page information that was available."
    if description:
        second = f"The page describes itself as {description}."
    elif paragraphs:
        second = paragraphs[0].rstrip(".") + "."
        if len(paragraphs) > 1:
            third = f"The article also explains {paragraphs[1].rstrip('.')}."
        else:
            third = "This summary is based on the main paragraph available on the page."
    elif headings:
        second = f"The main topics on the page include {', '.join(headings)}."
    elif page_text:
        second = f"The page begins with this content: {page_text[:180].rstrip()}."
    else:
        site_descriptions = {
            "reddit.com": "Reddit is a discussion and content-sharing website organized into communities.",
            "github.com": "GitHub is a platform for hosting software projects and collaborating on code.",
            "youtube.com": "YouTube is a video-sharing platform with channels, clips, and live content.",
            "wikipedia.org": "Wikipedia is a collaborative online encyclopedia with articles on many topics.",
        }
        clean_host = host.replace("www.", "", 1)
        second = site_descriptions.get(clean_host, f"The page does not provide enough readable content for a more detailed summary.")
    if details.get("error"):
        third = "The page did not expose readable content to the analyzer."
    return f"{first} {second} {third}"


async def safe_browsing_check(url: str) -> dict:
    if not SAFE_BROWSING_KEY:
        return {"available": False, "matches": []}

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={SAFE_BROWSING_KEY}"
    )
    payload = {
        "client": {"clientId": "simple-url-analyzer", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=2.5) as client:
            response = await client.post(endpoint, json=payload)
        response.raise_for_status()
        data = response.json()
        return {"available": True, "matches": data.get("matches", [])}
    except httpx.HTTPError as exc:
        return {"available": False, "matches": [], "error": str(exc)}


@app.get("/health")
def health():
    redis = get_redis()
    return {"status": "ok", "redis": redis is not None}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>URL Safety Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f4f6f8; color: #1d2733; margin: 0; }
    main { max-width: 760px; margin: 48px auto; padding: 0 20px; }
    form, section { background: white; border: 1px solid #dfe4ea; border-radius: 8px; padding: 22px; margin-top: 18px; }
    input { box-sizing: border-box; width: 78%; padding: 11px; border: 1px solid #bbc5d0; border-radius: 5px; font-size: 15px; }
    button { padding: 11px 16px; border: 0; border-radius: 5px; background: #2457d6; color: white; cursor: pointer; }
    .score { font-size: 48px; font-weight: bold; color: #2457d6; }
    .label { color: #5e6b78; }
    li { margin: 8px 0; }
    #error { color: #b42318; }
  </style>
</head>
<body>
  <main>
    <h1>URL Safety Dashboard</h1>
    <p>Enter a website link to check its safety and get a short summary.</p>
    <form id="form">
      <input id="url" type="url" placeholder="https://example.com" required>
      <button type="submit">Analyze</button>
    </form>
    <p id="error"></p>
    <section id="result" hidden>
      <div class="label">Health score</div>
      <div class="score" id="score"></div>
      <h2 id="status"></h2>
      <p id="availability"></p>
      <h3>Summary</h3>
      <p id="summary"></p>
      <h3>Warnings</h3>
      <ul id="warnings"></ul>
    </section>
  </main>
  <script>
    const form = document.getElementById('form');
    const result = document.getElementById('result');
    const error = document.getElementById('error');
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      result.hidden = true;
      error.textContent = '';
      try {
        const response = await fetch('/analyze', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({url: document.getElementById('url').value})
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Could not analyze this link');
        document.getElementById('score').textContent = `${data.health_score}/100`;
        document.getElementById('status').textContent = data.malicious ? 'Potentially unsafe' : (data.safety_status === 'checked' ? 'No known threat found' : 'Safety check incomplete');
        document.getElementById('availability').textContent = data.safe_browsing_available ? 'Google Safe Browsing check completed.' : 'Google Safe Browsing is unavailable; configure SAFE_BROWSING_KEY for a complete result.';
        document.getElementById('summary').textContent = data.summary;
        const warnings = document.getElementById('warnings');
        warnings.replaceChildren();
        (data.warnings.length ? data.warnings : ['No local warnings found']).forEach(item => {
          const li = document.createElement('li');
          li.textContent = item;
          warnings.appendChild(li);
        });
        result.hidden = false;
      } catch (err) {
        error.textContent = err.message;
      }
    });
  </script>
</body>
</html>
"""


@app.post("/analyze")
async def analyze(body: AnalyzeRequest, request: Request):
    url = str(body.url)

    redis = get_redis()
    client_ip = request.client.host if request.client else "unknown"
    if redis:
        rate_key = f"url-analyzer:rate:{client_ip}:{int(time.time()) // RATE_WINDOW_SECONDS}"
        count = redis.incr(rate_key)
        redis.expire(rate_key, RATE_WINDOW_SECONDS)
        if count > RATE_LIMIT:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        cached = redis.get(cache_key(url))
        if cached:
            result = json.loads(cached)
            result["cached"] = True
            return result

    checked = await safe_browsing_check(url)
    matches = checked["matches"]
    warnings = local_checks(url)
    details = await page_details(url)
    base_score = 0 if matches else (100 if checked["available"] else 85)
    score = max(0, base_score - (15 if "URL does not use HTTPS" in warnings else 0) - 10 * len(warnings))
    summary = await gemini_summary(url, details)
    if not summary:
        summary = make_summary(url, details)
    result = {
        "url": url,
        "safe": len(matches) == 0 and checked["available"],
        "malicious": len(matches) > 0,
        "safety_status": "unsafe" if matches else ("checked" if checked["available"] else "incomplete"),
        "health_score": score,
        "summary": summary,
        "matches": [
            {"threatType": item.get("threatType"), "platformType": item.get("platformType")}
            for item in matches
        ],
        "warnings": warnings,
        "safe_browsing_available": checked["available"],
        "cached": False,
    }
    if redis:
        redis.setex(cache_key(url), CACHE_SECONDS, json.dumps(result))
    return result
