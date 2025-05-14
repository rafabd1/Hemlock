# Hemlock

Cache poisoning detection tool.

## Overview

Hemlock is a Go-based tool designed to detect web cache poisoning vulnerabilities. It leverages advanced networking and concurrency techniques to efficiently scan and analyze web applications.

This project is based on the architectural discussions in:
- `dev/Hemlock-Archteture.md`
- `dev/ARCHITECTURE_NETWORKING_CONCURRENCY.md`

## Features (Planned)

- Concurrent scanning of multiple URLs.
- Resilient HTTP client with retries and backoff.
- Domain-specific state management for rate limiting and WAF detection.
- Detection of unkeyed inputs (headers, query parameters).
- Analysis of reflected inputs in responses.
- Customizable wordlists for headers and payloads.
- Structured reporting of findings.

## Getting Started

### Prerequisites

- Go (version X.Y.Z or higher)

### Installation

```bash
# Clone the repository
git clone https://github.com/rafabd1/Hemlock.git
cd Hemlock

# Build the project
go build ./cmd/hemlock
```

### Usage

```bash
./hemlock [options] <target_urls_file_or_stdin>
```

(Detailed usage instructions will be added as development progresses)

## Project Structure

- `cmd/hemlock/`: Main application entry point.
- `internal/`: Internal application logic (core, networking, input, report, utils).
- `pkg/`: Sharable libraries (if any).
- `wordlists/`: Directory for payload wordlists.
- `configs/`: Configuration files.
- `dev/`: Development documentation and architectural notes.

## Contributing

(Contribution guidelines will be added later)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
