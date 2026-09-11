"""Unit tests for technology fingerprinting engine."""

from webvuln.fingerprint.technologies import TechnologyFingerprinter
from webvuln.models.response import HTTPResponse


def test_fingerprint_server_and_php():
    res = HTTPResponse(
        url="http://target.local/",
        status_code=200,
        headers={
            "Server": "nginx/1.24.0",
            "X-Powered-By": "PHP/8.2.10",
            "Set-Cookie": "PHPSESSID=abcdef123456; path=/",
            "Content-Type": "text/html",
        },
        body="<html><body><h1>Hello World</h1></body></html>",
    )
    findings = TechnologyFingerprinter.analyze_response(res)
    assert "Nginx 1.24.0" in findings
    assert findings["Nginx 1.24.0"] >= 0.90
    assert "PHP 8.2.10" in findings
    assert findings["PHP 8.2.10"] >= 0.90


def test_fingerprint_react_and_django():
    res = HTTPResponse(
        url="http://target.local/app",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body="""
        <html>
            <head><meta name="generator" content="Django 4.2" /></head>
            <body>
                <input type="hidden" name="csrfmiddlewaretoken" value="abc123xyz" />
                <div id="root" data-reactroot=""></div>
                <script src="/static/js/react-dom.production.min.js"></script>
            </body>
        </html>
        """,
    )
    findings = TechnologyFingerprinter.analyze_response(res)
    assert "React" in findings
    assert "Django" in findings
    assert "Django 4.2" in findings
    assert findings["React"] >= 0.80
