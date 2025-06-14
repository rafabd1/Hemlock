# Hemlock Changelog

## [0.1.0] - 2025-06-13

### Initial Release

This is the first public release of Hemlock.

#### Core Features
- **Multi-faceted Scanning**: Detects cache poisoning vulnerabilities via:
    - Unkeyed HTTP Headers
    - Unkeyed URL Parameters
    - Cache Deception techniques
- **Two-Phase Analysis**: A robust two-phase process first identifies cacheable targets and then performs in-depth probing for vulnerabilities.
- **Concurrent Architecture**: Leverages Go's concurrency to perform fast, parallel scans across multiple targets and probes.
- **Domain-Aware Rate Limiting**: Smartly manages request rates per domain to avoid being blocked and handles `429 Too Many Requests` responses gracefully.
- **Simulation Mode**: Includes a `--simulate` flag to test the tool's logic and analysis engine without sending real network requests. This was instrumental in debugging and ensuring the reliability of the detection engine.
- **Flexible Configuration**: Highly configurable via CLI flags for:
    - Input targets (single URL, comma-separated list, file)
    - Concurrency levels for workers and probes
    - Timeouts and request retries
    - Specific test modes (`header`, `param`, `deception`)
    - Custom headers, proxy support, and rate limiting.
- **Reporting**: Generates reports in `JSON` or `text` format, which can be saved to a file or printed to stdout. 