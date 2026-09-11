"""Unit tests for link and parameter extraction."""

from webvuln.discovery.links import LinkExtractor
from webvuln.discovery.parameters import ParameterExtractor
from webvuln.models.request import HTTPMethod


def test_extract_links_from_html():
    html = """
    <html>
        <body>
            <a href="/about">About Us</a>
            <a href="https://other-domain.com/ad">External</a>
            <a href="contact.php?dept=sales">Contact</a>
            <script src="/static/app.js"></script>
        </body>
    </html>
    """
    links = LinkExtractor.extract_links(html, base_url="http://target.local")
    assert "http://target.local/about" in links
    assert "https://other-domain.com/ad" in links
    assert "http://target.local/contact.php?dept=sales" in links
    assert "http://target.local/static/app.js" in links


def test_extract_forms_and_inputs():
    html = """
    <form action="/login" method="POST">
        <input type="text" name="username" value="admin" />
        <input type="password" name="password" />
        <input type="hidden" name="csrf" value="token123" />
    </form>
    """
    forms = ParameterExtractor.extract_forms(html, base_url="http://target.local")
    assert len(forms) == 1
    form = forms[0]
    assert form.url == "http://target.local/login"
    assert form.method == HTTPMethod.POST
    assert form.form_data["username"] == "admin"
    assert "password" in form.form_data
    assert form.form_data["csrf"] == "token123"


def test_extract_query_parameters():
    url = "http://target.local/search?q=cyber&category=sec&page=2"
    params = ParameterExtractor.extract_query_parameters(url)
    assert params["q"] == "cyber"
    assert params["category"] == "sec"
    assert params["page"] == "2"
