from flask import Flask, request, redirect, make_response

app = Flask(__name__)

INDEX_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>Vulnerable Test App</title>
  <script src="/static/app.js" defer></script>
</head>
<body>
  <h1>Search</h1>
  <form action="/search" method="get">
    <input name="q" type="text" placeholder="Search...">
    <button type="submit">Search</button>
  </form>

  <!-- DOM XSS demo link: crawler will follow this and discover the callback param -->
  <h2>Features</h2>
  <ul>
    <li><a href="/?callback=hello">Load greeting widget</a></li>
    <li><a href="/?html=test">Load HTML widget</a></li>
    <li><a href="/admin">Admin Panel</a></li>
    <li><a href="/api">API Root</a></li>
    <li><a href="/api/search?q=test&callback=myFunc">API Search</a></li>
    <li><a href="/dashboard">Dashboard</a></li>
    <li><a href="/users?id=1">User Lookup</a></li>
    <li><a href="/redirect?url=/">Redirect</a></li>
    <li><a href="/set-lang?lang=en">Set Language</a></li>
    <li><a href="/delete-account?user=test">Delete Account</a></li>
  </ul>
  <div id="out"></div>
</body>
</html>
"""


SEARCH_PAGE = """
<!DOCTYPE html>
<html>
<body>
  <h2>Results for: {query}</h2>
  <p>You searched for the term above.</p>
  <form action="/search" method="get">
    <input name="q" type="text" placeholder="Search again...">
    <button type="submit">Search</button>
  </form>
  <a href="/">Back</a>
</body>
</html>
"""

@app.route('/')
def index():
    return INDEX_PAGE

@app.route('/search')
def search():
    q = request.args.get('q', '')
    # Intentionally unescaped -> reflected XSS on purpose, for testing only
    return SEARCH_PAGE.format(query=q)

@app.route('/admin')
def admin():
    return """
    <html><body>
    <h1>Admin Panel</h1>
    <form action="/admin/search" method="get">
      <input name="query" type="text" placeholder="Search users...">
      <button type="submit">Search</button>
    </form>
    </body></html>
    """

@app.route('/admin/search')
def admin_search():
    query = request.args.get('query', '')
    # Another reflected XSS vector for testing
    return f"<html><body><h2>Admin Results: {query}</h2></body></html>"

@app.route('/api')
def api():
    return '{"status": "ok", "endpoints": ["/api/search", "/api/users"]}'

@app.route('/api/search')
def api_search():
    q = request.args.get('q', '')
    # JSON with unescaped input for JSONP-style testing
    callback = request.args.get('callback', '')
    if callback:
        return f"{callback}({{'result': '{q}'}})"
    return f'{{"result": "{q}"}}'

@app.route('/dashboard')
def dashboard():
    return "<html><body><h1>Dashboard</h1><p>Welcome back.</p></body></html>"

@app.route('/login')
def login():
    return """
    <html><body>
    <h1>Login</h1>
    <form action="/login" method="post">
      <input name="username" type="text" placeholder="Username">
      <input name="password" type="password" placeholder="Password">
      <button type="submit">Login</button>
    </form>
    </body></html>
    """

# ── SQLI simulation ──────────────────────────────────────────────────────────
@app.route('/users')
def users():
    uid = request.args.get('id', '1')
    # Intentionally vulnerable: raw user input embedded in SQL-like query string
    # (simulated - not a real DB, but the pattern is detectable)
    fake_query = f"SELECT * FROM users WHERE id={uid}"
    return f"<html><body><h2>User Lookup</h2><p>Query: {fake_query}</p></body></html>"

# ── Open Redirect ────────────────────────────────────────────────────────────
@app.route('/redirect')
def open_redirect():
    url = request.args.get('url', '/')
    # VULNERABLE: user-controlled redirect destination without validation
    return redirect(url)

# ── HTTP Response Header Injection ──────────────────────────────────────────
@app.route('/set-lang')
def set_lang():
    lang = request.args.get('lang', 'en')
    # VULNERABLE: user input injected directly into response header
    resp = make_response(f"<html><body><p>Language set to: {lang}</p></body></html>")
    resp.headers['X-App-Language'] = lang
    return resp

# ── CSRF-less state change ───────────────────────────────────────────────────
@app.route('/delete-account')
def delete_account():
    username = request.args.get('user', '')
    # VULNERABLE: state-changing action via GET with no CSRF token
    return f"<html><body><h2>Account '{username}' deleted (no CSRF protection)</h2></body></html>"

@app.route('/static/app.js')
def appjs():
    js = """
    // DOM-Based XSS: reads 'callback' URL param and injects into innerHTML
    var params = new URLSearchParams(window.location.search);
    var cb = params.get('callback');
    if (cb) {
        // VULNERABLE: user-controlled data injected directly into innerHTML
        document.getElementById('out').innerHTML = cb;
    }
    // Also reads 'html' param for a second DOM XSS vector
    var html = params.get('html');
    if (html) {
        document.getElementById('out').innerHTML = html;
    }
    """
    return js, 200, {'Content-Type': 'application/javascript'}

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)