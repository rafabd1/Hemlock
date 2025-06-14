from flask import Flask, make_response

app = Flask(__name__)

@app.route('/')
def index():
    # This is a safe, non-vulnerable application.
    # It does not reflect any user-controllable input.
    body = "<h1>Control Application</h1><p>This is a safe page and should not trigger any findings.</p>"
    response = make_response(body, 200)
    response.headers['Content-Type'] = 'text/html'
    return response

if __name__ == '__main__':
    # Running on port 5004, which is what Varnish expects for this backend.
    app.run(host='0.0.0.0', port=5004) 