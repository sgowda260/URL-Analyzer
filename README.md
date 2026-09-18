# URL Analyzer

This is a simple FastAPI dashboard for reviewing website safety. Upon inserting a URL, it'll check links with Google Safe Browsing, calculate a basic health score, identify URL warnings, and provide a short website summary using available page details or Gemini. This project uses Redis for caching and rate limiting and keeps the Python application in a single file.
