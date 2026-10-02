from flask import Flask, request

app = Flask(__name__)

INDEX_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>Vulnerable Test App</title>
  <script src="/static/app.js"></script>
</head>
<body>
  <h1>Search</h1>
  <form action="/search" method="get">
    <input name="q" type="text">
    <button type="submit">Search</button>
  </form>
  <div id="out"></div>
</body>
</html>
"""

SEARCH_PAGE = """
<!DOCTYPE html>
<html>
<body>
  <h2>Results for: {query}</h2>
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
    return "Admin panel placeholder (for gobuster to discover)"

@app.route('/api')
def api():
    return "API root placeholder (for gobuster to discover)"

@app.route('/login')
def login():
    return "Login page placeholder (for gobuster to discover)"

@app.route('/static/app.js')
def appjs():
    js = """
    var params = new URLSearchParams(window.location.search);
    var cb = params.get('callback');
    if (cb) {
        document.getElementById('out').innerHTML = cb;
    }
    """
    return js, 200, {'Content-Type': 'application/javascript'}

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)