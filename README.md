# Hemlock

![Go Version](https://img.shields.io/github/go-mod/go-version/rafabd1/Hemlock)
![Release](https://img.shields.io/github/v/release/rafabd1/Hemlock?include_prereleases)
![Build Status](https://github.com/rafabd1/Hemlock/workflows/Release%20Hemlock/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/rafabd1/Hemlock?style=social)
![Go Report Card](https://goreportcard.com/badge/github.com/rafabd1/Hemlock)

<div align="center">
<pre>
   _    _                _            _    
  | |  | |              | |          | |   
  | |__| | ___ _ __ ___ | | ___   ___| | __
  |  __  |/ _ \ '_ \`_ \| |/ _ \ / __| |/ /
  | |  | |  __/ | | | | | | (_) | (__|   < 
  |_|  |_|\___|_| |_| |_|_|\___/ \___|_|\_\
</pre>
</div>

<p align="center">
    <b>A powerful and fast CLI tool for detecting Web Cache Poisoning vulnerabilities.</b>
</p>

## Features

- **Multi-faceted Scanning**: Detects cache poisoning vulnerabilities via unkeyed headers, unkeyed parameters, and cache deception techniques. For safety, deception tests append a cache-busting parameter to avoid poisoning the cache for legitimate users.
- **Two-Phase Analysis**: A robust two-phase process first identifies cacheable targets and then performs in-depth probing for vulnerabilities.
- **Concurrent Architecture**: Leverages Go's concurrency to perform fast, parallel scans across multiple targets and probes.
- **Domain-Aware Rate Limiting**: Smartly manages request rates per domain to avoid being blocked and handles `429 Too Many Requests` responses gracefully.
- **Simulation Mode**: Includes a `--simulate` flag to test the tool's logic and analysis engine without sending real network requests, perfect for CI/CD and debugging.
- **Flexible Configuration**: Highly configurable via CLI flags for concurrency, timeouts, test modes, custom headers, and more.
- **Multiple Output Formats**: Supports both `text` and `json` output formats for easy integration with other tools.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/rafabd1/Hemlock.git
cd Hemlock

# Install dependencies
go mod download

# Build the binary
go build -o hemlock ./cmd/hemlock

# Optional: Move to path (Linux/macOS)
sudo mv hemlock /usr/local/bin/

# Optional: Add to PATH (Windows - in PowerShell as Admin)
# Copy-Item .\hemlock.exe C:\Windows\System32\
```

### Using Go Install

```bash
go install github.com/rafabd1/Hemlock/cmd/hemlock@latest
```

### Binary Releases

You can download pre-built binaries for your platform from the [releases page](https://github.com/rafabd1/Hemlock/releases).

## Quick Start

Scan a single URL for all test types:
```bash
hemlock -i http://example.com --test-modes header,param,deception
```

Scan a URL for just cache deception vulnerabilities with high verbosity:
```bash
hemlock -i http://vulnerable.site/index.html -vv --test-modes deception
```

Scan from a list of URLs and save results to a JSON file:
```bash
hemlock -i url-list.txt -o results.json
```

Use simulation mode to test the logic without sending real requests:
```bash
hemlock -i http://test.com --simulate -vv --test-modes header,param,deception
```

## Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --input` | Input: URL, comma-separated URLs, or path to a file with URLs. | - |
| `--test-modes` | Comma-separated list of test modes to run (header, param, deception). | `header` |
| `--headers-file` | Path to the file of headers to test. | `wordlists/headers.txt` |
| `--param-wordlist` | Path to the file of parameters to fuzz. | `wordlists/params.txt` |
| `-H, --header` | Custom HTTP header to add to ALL requests (can be specified multiple times). | - |
| `-o, --output-file` | Path to file for saving results (default: stdout). | - |
| `--output-format` | Output format: json or text. | `json` |
| `-c, --concurrency` | Number of concurrent workers (overall URL processing). | `10` |
| `-p, --probes` | Number of concurrent probes (e.g., header/param tests) per URL. | `4` |
| `-t, --timeout` | HTTP request timeout in seconds. | `10` |
| `-r, --max-retries` | Maximum number of retries per request. | `3` |
| `-l, --rate-limit` | Max requests per second per domain (0 for auto-adjustment). | `0.0` |
| `--insecure` | Disable TLS certificate verification. | `false` |
| `-v, --verbose` | Verbosity level (-v for debug, -vv for more debug). | - |
| `--no-color` | Disable colors in text output. | `false` |
| `--silent` | Suppress all logs except fatal errors and final results. | `false` |
| `--proxy` | Proxy to use (URL, CSV list, or file path). | - |
| `--simulate` | Enable simulation mode to test logic without real network requests. | `false` |

## Disclaimer

**Usage Warning & Responsibility**

This tool is intended for security professionals and researchers for legitimate testing purposes only. Running Hemlock against a target will generate a high volume of HTTP requests, which could be disruptive. To avoid potential IP blocks or rate limiting, it is highly recommended to use proxies via the `--proxy` flag.

The user is responsible for their actions and must have explicit permission to test any target. The author of this tool is not responsible for any misuse or damage caused by this program.

## Documentation

- [Changelog](CHANGELOG.md) - Check the latest updates and version history.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1.  Fork the repository
2.  Create your feature branch (`git checkout -b feature/amazing-feature`)
3.  Commit your changes (`git commit -m 'Add some amazing feature'`)
4.  Push to the branch (`git push origin feature/amazing-feature`)
5.  Open a Pull Request

## License

This project is licensed under the MIT License.

## Acknowledgements

- Built with [Go](https://golang.org/)
- Uses [Cobra](https://github.com/spf13/cobra) and [Viper](https://github.com/spf13/viper) for CLI functionality.



<p align="center">
    <sub>Made with 🖤 by Rafael (github.com/rafabd1)</sub>
</p>

<p align="center">
    <a href="https://ko-fi.com/rafabd1" target="_blank"><img src="https://storage.ko-fi.com/cdn/kofi2.png?v=3" alt="Buy Me A Coffee" style="height: 60px !important;"></a>
</p>
