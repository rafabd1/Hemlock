from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/')
def index():
    # This is the vulnerable part.
    # It reflects the 'utm_source' parameter, which our Varnish config intentionally ignores.
    # A payload like '?utm_source=<script>alert(1)</script>' will be reflected and cached.
    source = request.args.get('utm_source')
    
    if source:
        # If the parameter is present, reflect it.
        body = f"<h1>Welcome!</h1><p>Content from source: <b>{source}</b></p>"
    else:
        # If the parameter is not present, show a default message.
        body = "<h1>Welcome!</h1><p>This is the default content for the parameter test app.</p>"
        
    response = make_response(body, 200)
    response.headers['Content-Type'] = 'text/html'
    return response

if __name__ == '__main__':
    # Running on port 5002, which is what Varnish expects for this backend.
    app.run(host='0.0.0.0', port=5002) 