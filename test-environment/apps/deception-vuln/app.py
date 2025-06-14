from flask import Flask, make_response

app = Flask(__name__)

# The cache deception vulnerability happens when a request for what looks like
# a static asset (e.g., /static/style.css;/nonexistent) is routed here by the proxy.
# The cache then incorrectly caches this HTML response for the static asset URL.
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    body = "<h1>Cache Deception Test Page</h1><p>If you see this on a URL that should be a static asset, the test worked.</p>"
    response = make_response(body, 200)
    response.headers['Content-Type'] = 'text/html'
    # Adding a header to make it clear this is from the deception app backend
    response.headers['X-App-Name'] = 'Deception-Vuln-App'
    return response

if __name__ == '__main__':
    # Running on port 5003, which is what Varnish expects for this backend.
    app.run(host='0.0.0.0', port=5003) 