# Hemlock Test Environment

This directory contains a Docker-based test environment for the Hemlock Web Cache Poisoning scanner. It uses Docker Compose to set up a Varnish cache server in front of several intentionally vulnerable (and one non-vulnerable) Python Flask applications.

This allows for consistent and reliable testing of Hemlock's detection capabilities.

## Services

1.  **Varnish (`varnish-cache`)**: The caching proxy, accessible on `http://localhost:8080`. It is configured in `varnish/default.vcl` to be vulnerable.
2.  **Header Poisoning App (`app-header-vuln`)**: A Flask app that reflects the `X-Forwarded-Host` header. Accessed via the `header-vuln.test` Host header.
3.  **Parameter Poisoning App (`app-param-vuln`)**: A Flask app that reflects the `utm_source` parameter. Accessed via the `param-vuln.test` Host header.
4.  **Cache Deception App (`app-deception-vuln`)**: A Flask app that serves a generic HTML page for any path. Accessed via the `deception-vuln.test` Host header.
5.  **Control App (`app-control`)**: A non-vulnerable app to test for false positives. Accessed via any other Host header (e.g., `control.test`).

## How to Use

### Prerequisites
- Docker
- Docker Compose

### 1. Start the Environment

Navigate to this directory (`/test-environment`) in your terminal and run:

```bash
docker-compose up --build -d
```
This will build the images for all services and start them in the background.

### 2. Run Hemlock Tests

Once the environment is running, you can run Hemlock against the test targets. The Varnish server is listening on `http://localhost:8080`.

You will need to use a `Host` header to specify which backend application to target.

**Example Test Commands:**

*   **Test for Header Poisoning:**
    ```bash
    go run ./cmd/hemlock -i http://localhost:8080 -H "Host: header-vuln.test" --test-modes header
    ```

*   **Test for Parameter Poisoning:**
    ```bash
    go run ./cmd/hemlock -i "http://localhost:8080/?p=1" -H "Host: param-vuln.test" --test-modes param
    ```

*   **Test for Cache Deception:**
    ```bash
    go run ./cmd/hemlock -i http://localhost:8080/style.css -H "Host: deception-vuln.test" --test-modes deception
    ```
    
*   **Test the Control (should find nothing):**
    ```bash
    go run ./cmd/hemlock -i http://localhost:8080 -H "Host: control.test" --test-modes header,param,deception
    ```

### 3. Stop the Environment

When you are finished testing, you can stop and remove the containers:

```bash
docker-compose down
``` 