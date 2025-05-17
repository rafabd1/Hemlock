package utils

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/rafabd1/Hemlock/internal/config" // For config.ProxyEntry
)

// ParseProxyInput parses a proxy input string (which can be a single proxy URL,
// a comma-separated list of proxy URLs, or a file path containing one proxy URL per line)
// into a slice of ProxyEntry structs.
func ParseProxyInput(proxyInput string, logger Logger) ([]config.ProxyEntry, error) {
	if proxyInput == "" {
		return nil, nil
	}

	var proxyStrings []string

	// Attempt to read as a file first
	// Check if the input string could be a file path (basic check, might need refinement)
	// For simplicity, we'll assume if it doesn't contain typical URL chars like ':' or '@' before a certain point
	// and is not obviously a URL, it might be a file. A more robust check would be os.Stat.
	if _, err := os.Stat(proxyInput); err == nil {
		logger.Debugf("Proxy input '%s' appears to be a file. Attempting to read.", proxyInput)
		file, errOpen := os.Open(proxyInput)
		if errOpen != nil {
			logger.Warnf("Failed to open proxy file '%s', treating input as literal string: %v", proxyInput, errOpen)
			// Fallback to treating proxyInput as a literal list if file open fails despite stat succeeding (e.g. permissions)
			proxyStrings = strings.Split(proxyInput, ",")
		} else {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					proxyStrings = append(proxyStrings, line)
				}
			}
			if errScan := scanner.Err(); errScan != nil {
				return nil, fmt.Errorf("error reading proxy file '%s': %w", proxyInput, errScan)
			}
			logger.Debugf("Loaded %d proxy strings from file '%s'", len(proxyStrings), proxyInput)
		}
	} else {
		// Not a file (or stat failed), treat as comma-separated list or single proxy
		logger.Debugf("Proxy input '%s' does not appear to be a file or file not found. Treating as literal string(s).", proxyInput)
		proxyStrings = strings.Split(proxyInput, ",")
	}

	var parsedProxies []config.ProxyEntry
	for _, str := range proxyStrings {
		trimmedStr := strings.TrimSpace(str)
		if trimmedStr == "" {
			continue
		}

		// Attempt to parse the proxy string
		// Format: [scheme://][user:pass@]host:port
		var scheme, user, pass, host, port string

		// Default scheme
		scheme = "http"

		urlStr := trimmedStr
		if !strings.Contains(urlStr, "://") {
			urlStr = "http://" + urlStr // Prepend default scheme if not present for URL parser
		}

		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			logger.Warnf("Failed to parse proxy string '%s' (as URL '%s'): %v. Skipping this proxy.", trimmedStr, urlStr, err)
			continue
		}

		if parsedURL.Scheme != "" {
			scheme = parsedURL.Scheme
		}

		host = parsedURL.Hostname()
		port = parsedURL.Port()

		if parsedURL.User != nil {
			user = parsedURL.User.Username()
			pass, _ = parsedURL.User.Password()
		}

		if host == "" {
			logger.Warnf("Proxy string '%s' resulted in empty host. Skipping.", trimmedStr)
			continue
		}
		if port == "" {
			// Try to extract host and port if url.Parse didn't get it (e.g. if no scheme was prepended and it was just host:port)
			parts := strings.Split(trimmedStr, ":")
			if len(parts) == 2 && host == parts[0] { // host matched, so second part is likely port
				port = parts[1]
			} else if len(parts) > 1 && !strings.Contains(trimmedStr, "://") { // if host:port:user:pass format, for example.
			    // This is a simplified parsing for direct host:port or user:pass@host:port if url.Parse failed it.
			    // More complex manual parsing might be needed for non-URL formats not caught by url.Parse
			    // For now, if url.Parse didn't get a port, and it's not a simple host:port, we might miss it.
			    // Let's re-evaluate if host is set but port is not.
			    // If the original string (trimmedStr) did not have a scheme, url.Parse might misinterpret host:port.
			    if !strings.Contains(trimmedStr, "://") { // It was likely a host:port type string
			        hostPortParts := strings.SplitN(trimmedStr, "@", 2)
			        var actualHostPortPart string
			        if len(hostPortParts) == 2 { // Contains user:pass@
			            userInfoParts := strings.SplitN(hostPortParts[0], ":", 2)
			            user = userInfoParts[0]
			            if len(userInfoParts) == 2 {pass = userInfoParts[1]}
			            actualHostPortPart = hostPortParts[1]
			        } else { // No user:pass@
			            actualHostPortPart = hostPortParts[0]
			        }

			        finalSplit := strings.SplitN(actualHostPortPart, ":", 2)
			        if len(finalSplit) == 2 {
			            host = finalSplit[0]
			            port = finalSplit[1]
			        } else {
			             host = finalSplit[0] // no port
			        }
			    }
			    if port == "" { // still no port
			        logger.Warnf("Proxy string '%s' resulted in empty port after attempting to manually parse host:port. Skipping.", trimmedStr)
			        continue
			    }
			}
		}

		// Construct the full host string (hostname:port)
		fullHost := host
		if port != "" {
			fullHost = net.JoinHostPort(host, port)
		}

		// Reconstruct a canonical URL for the ProxyEntry.URL field, including user info if present
		var entryURL string
		empURL := url.URL{
			Scheme: scheme,
			Host:   fullHost,
		}
		if user != "" {
			empURL.User = url.UserPassword(user, pass)
		}
		entryURL = empURL.String()

		parsedProxies = append(parsedProxies, config.ProxyEntry{
			URL:      entryURL, // Store the reconstructed, canonical URL
			Scheme:   scheme,
			Host:     fullHost, // Store as host:port
			Username: user,     // Correct field name
			Password: pass,
		})
	}

	if len(proxyStrings) > 0 && len(parsedProxies) == 0 {
		return nil, fmt.Errorf("proxy input '%s' provided, but no valid proxies could be parsed", proxyInput)
	} else if len(parsedProxies) > 0 {
	    logger.Infof("Successfully parsed %d proxies.", len(parsedProxies))
	    for _, p := range parsedProxies {
	        // Use p.String() which should be defined in config.ProxyEntry and handles formatting.
	        // Or, if logging specific parsed components:
	        logger.Debugf("Parsed proxy details: Scheme: %s, Host: %s, Username: %s, Full: %s", p.Scheme, p.Host, p.Username, p.String())
	    }
	}

	return parsedProxies, nil
} 