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

		var scheme, user, pass, host, port string
		scheme = "http" // Default scheme

		// Tentativa 1: Usar url.Parse para formatos padrão (scheme://user:pass@host:port)
		parsedAsURL := false
		if strings.Contains(trimmedStr, "://") {
			if parsedURL, err := url.Parse(trimmedStr); err == nil {
				if parsedURL.Scheme != "" { scheme = parsedURL.Scheme }
				host = parsedURL.Hostname()
				port = parsedURL.Port()
				if parsedURL.User != nil {
					user = parsedURL.User.Username()
					pass, _ = parsedURL.User.Password()
				}
				if host != "" && port != "" {
					parsedAsURL = true
				} else {
					// url.Parse pode ter sucesso parcial, ex: "http://semporta"
					// Resetamos para tentar o fallback se host ou porta estiverem faltando.
					scheme = "http" // Reset to default
					host, port, user, pass = "", "", "", ""
				}
			}
		}

		// Tentativa 2: Fallback para formatos como user:pass@host:port ou host:port ou ip:port:user:pass
		if !parsedAsURL {
			parts := strings.Split(trimmedStr, "@")
			mainPart := ""
			if len(parts) == 2 { // Contém user:pass@
				userInfoParts := strings.SplitN(parts[0], ":", 2)
				user = userInfoParts[0]
				if len(userInfoParts) == 2 {
					pass = userInfoParts[1]
				}
				mainPart = parts[1]
			} else { // Não contém user:pass@
				mainPart = parts[0]
			}

			// Agora, mainPart pode ser host:port ou ip:port:user:pass (se user/pass não foram pegos antes)
			// ou apenas host (se não houver porta)
			colParts := strings.Split(mainPart, ":")
			if len(colParts) >= 2 { // Pelo menos host:port
				host = colParts[0]
				port = colParts[1]
				if len(colParts) == 4 && user == "" && pass == "" { // Formato ip:port:user:pass e user/pass ainda não definidos
					// Isso sugere que o formato original era ip:port:user:pass
					// Se user e pass já foram preenchidos pelo split com "@", não sobrescrever aqui.
					user = colParts[2]
					pass = colParts[3]
					// Neste caso, o 'scheme' permanece o default "http"
				} else if len(colParts) > 2 && (user != "" || pass != "") {
					// Se já tínhamos user/pass (de user:pass@host:port:something_else),
					// e há mais de duas partes após o '@', isso é um formato estranho.
					// Por enquanto, apenas pegamos host e port.
					logger.Warnf("Proxy string '%s' has an unusual format after '@'. Using host='%s', port='%s'. Extra parts: %v", trimmedStr, host, port, colParts[2:])
				}
			} else if len(colParts) == 1 { // Apenas host, sem porta
				host = colParts[0]
				// Port fica vazio, o que será tratado abaixo
			}
		}

		if host == "" {
			logger.Warnf("Proxy string '%s' resulted in empty host. Skipping.", trimmedStr)
			continue
		}
		if port == "" {
			// Se a porta ainda estiver vazia, logar e pular.
			// Poderíamos ter um default (ex: 80 ou 8080), mas é melhor exigir.
			logger.Warnf("Proxy string '%s' resulted in empty port. Skipping.", trimmedStr)
			continue
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
	    logger.Debugf("Successfully parsed %d proxies.", len(parsedProxies))
	    for _, p := range parsedProxies {
	        // Use p.String() which should be defined in config.ProxyEntry and handles formatting.
	        // Or, if logging specific parsed components:
	        logger.Debugf("Parsed proxy details: Scheme: %s, Host: %s, Username: %s, Full: %s", p.Scheme, p.Host, p.Username, p.String())
	    }
	}

	return parsedProxies, nil
} 