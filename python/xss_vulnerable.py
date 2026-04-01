"""
Vulnerable Python code with XSS flaws.
For security scanner testing only.
"""
from flask import Flask, request, render_template_string
from django.utils.safestring import mark_safe

app = Flask(__name__)


@app.route('/search')
def search_vulnerable():
    """XSS via render_template_string with user input."""
    query = request.args.get('q', '')
    template = f"<h1>Results for: {query}</h1>"
    return render_template_string(template)


@app.route('/greet')
def greet_vulnerable():
    """XSS via string concatenation in template."""
    name = request.args.get('name', '')
    html = "<h1>Hello " + name + "</h1>"
    return render_template_string(html)


@app.route('/message')
def message_vulnerable():
    """XSS via format string in template."""
    msg = request.args.get('msg', '')
    return render_template_string("<div>{}</div>".format(msg))


def django_mark_safe_vulnerable(user_input):
    """Django XSS via mark_safe."""
    content = mark_safe(user_input)
    return content


@app.route('/profile')
def profile_safe():
    """Safe version using Jinja2 auto-escaping."""
    username = request.args.get('username', '')
    return render_template('profile.html', username=username)
