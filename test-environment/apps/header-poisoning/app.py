from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/')
def index():
    # This is the vulnerable part.
    # It blindly takes the 'X-Forwarded-Host' header and reflects it in the response.
    # A cache poisoning payload like 'X-Forwarded-Host: evil.com' will be cached.
    forwarded_host = request.headers.get('X-Forwarded-Host')
    
    if forwarded_host:
        # If the header is present, reflect it.
        body = f"<h1>Welcome!</h1><p>This content is served from the host: <b>{forwarded_host}</b></p>"
    else:
        # If the header is not present, show a default message.
        body = "<h1>Welcome!</h1><p>This is the default content.</p>"
        
    response = make_response(body, 200)
    response.headers['Content-Type'] = 'text/html'
    return response

if __name__ == '__main__':
    # Running on port 5001, which is what Varnish expects for this backend.
    app.run(host='0.0.0.0', port=5001) 