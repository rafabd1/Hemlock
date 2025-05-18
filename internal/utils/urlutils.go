package utils

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

var (
	// schemePattern verifica se a URL começa com um esquema como http:// ou https://
	schemePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+-.]*://`)

	// protocolRelativePattern verifica se a URL começa com // (protocol-relative)
	protocolRelativePattern = regexp.MustCompile(`^//`)
)

// normalizeURL normalizes a URL for more effective deduplication.
// It converts the scheme and host to lowercase, removes 'www.' prefix from the host,
// and sorts query parameters.
func normalizeURL(rawURL string, logger Logger) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		logger.Debugf("Failed to parse URL for normalization: %s, error: %v", rawURL, err)
		return rawURL, err // Return original on parse error
	}

	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	host = strings.TrimPrefix(host, "www.")
	u.Host = host

	// Sort query parameters
	if u.RawQuery != "" {
		query := u.Query()
		sortedQuery := make(url.Values)
		var keys []string
		for k := range query {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			// Sort values for each key as well, for stricter normalization
			values := query[k]
			sort.Strings(values)
			for _, v := range values {
				sortedQuery.Add(k, v) // Add preserves order for multiple values of same key
			}
		}
		u.RawQuery = sortedQuery.Encode()
	}

	return u.String(), nil
}

// PreprocessURLs filters and deduplicates a list of URLs.
// - Normalizes URLs for better deduplication.
// - Removes exact duplicates after normalization.
// - Filters out URLs with specified (case-insensitive) file extensions.
func PreprocessURLs(rawURLs []string, ignoredExtensions []string, stripWWW bool, logger Logger) []string {
	if len(rawURLs) == 0 {
		return []string{}
	}

	processedURLs := make(map[string]bool)
	var resultURLs []string
	var lowerIgnoredExtensions []string
	for _, ext := range ignoredExtensions {
		lowerIgnoredExtensions = append(lowerIgnoredExtensions, strings.ToLower(ext))
	}

	logger.Infof("Starting preprocessing for %d raw URLs.", len(rawURLs))

	for _, rawURL := range rawURLs {
		u, err := url.Parse(rawURL)
		if err != nil {
			logger.Warnf("Skipping URL due to parse error during preprocessing: %s, error: %v", rawURL, err)
			continue
		}

		// Filter by extension
		ext := strings.ToLower(path.Ext(u.Path))
		isIgnored := false
		for _, ignoredExt := range lowerIgnoredExtensions {
			if ext == ignoredExt {
				isIgnored = true
				break
			}
		}
		if isIgnored {
			logger.Debugf("Filtering out URL %s due to ignored extension: %s", rawURL, ext)
			continue
		}

		// Normalize for deduplication
		// The stripWWW logic is now handled within normalizeURL's host processing if needed,
		// but the parameter can be kept if we want to make it more explicit or configurable elsewhere.
		// For now, normalizeURL will always trim 'www.' for consistent deduplication.
		normalizedURL, err := normalizeURL(rawURL, logger)
		if err != nil {
			// Already logged in normalizeURL, or could log again if we want specific context here
			// For simplicity, assume it's logged. We might still want to add the rawURL if it wasn't processed.
			// Let's add the non-normalized version if normalization fails to avoid losing it entirely,
			// unless the error from normalizeURL suggests it's fundamentally invalid.
			// Current normalizeURL returns original on parse error, so it's fine.
		}


		if _, exists := processedURLs[normalizedURL]; !exists {
			processedURLs[normalizedURL] = true
			resultURLs = append(resultURLs, rawURL) // Add the original URL that passed filters
		}
	}

	logger.Infof("Finished preprocessing. %d URLs remain after filtering and deduplication.", len(resultURLs))
	return resultURLs
}

// ExtractRelevantToken attempts to extract a meaningful token from an injected value.
// If the value parses as a URL with a hostname, the hostname is returned.
// Otherwise, the original value is returned.
func ExtractRelevantToken(injectedValue string) string {
	if injectedValue == "" {
		return ""
	}
	u, err := url.Parse(injectedValue)
	if err == nil && u != nil && u.Hostname() != "" {
		// It's a URL and has a hostname, return the hostname
		return u.Hostname()
	}
	// Not a URL with a clear hostname, or parsing failed; return the original value
	return injectedValue
} 

// PreprocessAndGroupURLs normalizes URLs, extracts base URLs, and groups their query parameters.
// It returns a map of base URLs to a list of their original query parameter sets,
// a sorted list of unique base URLs, the total count of query parameters found across all sets,
// and the count of base URLs that have parameters.
func PreprocessAndGroupURLs(rawURLs []string, logger Logger) (map[string][]map[string]string, []string, int, int) {
	groupedParams := make(map[string][]map[string]string)
	baseURLExistence := make(map[string]struct{})
	var uniqueBaseURLs []string
	totalQueryParametersFound := 0
	baseURLsWithParamsCount := 0

	if logger == nil {
		// Provide a no-op logger if nil is passed to prevent panics
		logger = &NoOpLogger{}
	}

	// Define a default list of extensions to ignore for cache poisoning tests
	// TODO: This list could be made configurable in the future
	defaultIgnoredExtensions := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot", // Common web assets
		".map",                         // Source maps
		".xml", ".json", ".txt",       // Common data files (unless specifically targeted)
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", // Documents
		".zip", ".tar", ".gz", ".rar", // Archives
		".mp4", ".avi", ".mov", ".webm", // Video
		".mp3", ".wav", ".ogg", // Audio
		".ico",                                                        // Favicons
		".d.ts", ".ts", ".tsx", ".jsx", // TypeScript/JavaScript specific build/type files
		".vue", ".svelte", // Framework specific files
		// Consider adding more based on typical non-HTML, non-dynamic content
	}
	lowerIgnoredExtensions := make([]string, len(defaultIgnoredExtensions))
	for i, ext := range defaultIgnoredExtensions {
		lowerIgnoredExtensions[i] = strings.ToLower(ext)
	}

	for _, rawURL := range rawURLs {
		// Attempt to parse the raw URL early to check its extension first
		parsedForExtCheck, errExtCheck := url.Parse(rawURL)
		if errExtCheck != nil {
			logger.Warnf("Skipping URL due to initial parse error (for extension check): %s, error: %v", rawURL, errExtCheck)
			continue
		}

		// Filter by extension
		currentExtension := strings.ToLower(path.Ext(parsedForExtCheck.Path))
		if currentExtension != "" { // Only check if there is an extension
			isIgnored := false
			for _, ignoredExt := range lowerIgnoredExtensions {
				if currentExtension == ignoredExt {
					isIgnored = true
					break
				}
			}
			if isIgnored {
				continue
			}
		}

		normalizedFullURL, err := normalizeURL(rawURL, logger) // Normalizes scheme, host, sorts params etc.
		if err != nil {
			logger.Warnf("Skipping URL due to normalization error: %s, error: %v", rawURL, err)
			continue
		}

		u, err := url.Parse(normalizedFullURL) // Parse the already normalized URL
		if err != nil {
			logger.Warnf("Skipping URL due to parse error after normalization: %s, error: %v", normalizedFullURL, err)
			continue
		}

		// Construct base URL (scheme + host + path)
		baseURL := &url.URL{
			Scheme: u.Scheme,
			Host:   u.Host,
			Path:   u.Path,
		}
		baseString := baseURL.String()

		queryParamsMap := make(map[string]string)
		originalURLParsed, parseErr := url.Parse(rawURL)
		if parseErr == nil {
			for k, v := range originalURLParsed.Query() {
				if len(v) > 0 {
					queryParamsMap[k] = v[0]
				}
			}
		}

		if _, exists := baseURLExistence[baseString]; !exists {
			baseURLExistence[baseString] = struct{}{}
			uniqueBaseURLs = append(uniqueBaseURLs, baseString)
		}
		groupedParams[baseString] = append(groupedParams[baseString], queryParamsMap)
	}

	sort.Strings(uniqueBaseURLs)

	// Deduplicate parameter sets and count parameters
	tempGroupedParams := make(map[string][]map[string]string)
	for base, paramSets := range groupedParams {
		dedupedSets := []map[string]string{}
		seenSets := make(map[string]struct{})
		currentBaseHasParams := false
		for _, pSet := range paramSets {
			var paramKeys []string
			for k := range pSet {
				paramKeys = append(paramKeys, k)
			}
			sort.Strings(paramKeys)
			var canonicalParts []string
			for _, k := range paramKeys {
				canonicalParts = append(canonicalParts, k+"="+pSet[k])
			}
			canonicalString := strings.Join(canonicalParts, "&")

			if _, seen := seenSets[canonicalString]; !seen {
				seenSets[canonicalString] = struct{}{}
				dedupedSets = append(dedupedSets, pSet)
				if len(pSet) > 0 {
					totalQueryParametersFound += len(pSet)
					currentBaseHasParams = true
				}
			}
		}
		tempGroupedParams[base] = dedupedSets
		if currentBaseHasParams {
			baseURLsWithParamsCount++
		}
	}
	groupedParams = tempGroupedParams // Update with deduped sets

	logger.Debugf("Preprocessed URLs. Found %d unique base URLs after filtering.", len(uniqueBaseURLs)) // Updated log to Debugf
	logger.Debugf("Total query parameters found across all unique sets: %d", totalQueryParametersFound)
	logger.Debugf("Number of base URLs with parameters: %d", baseURLsWithParamsCount)

	return groupedParams, uniqueBaseURLs, totalQueryParametersFound, baseURLsWithParamsCount
}

// NoOpLogger is a logger that does nothing, useful for utility functions
// where a logger might not always be provided.
type NoOpLogger struct{}

func (l *NoOpLogger) Debugf(format string, args ...interface{}) {}
func (l *NoOpLogger) Infof(format string, args ...interface{})  {}
func (l *NoOpLogger) Warnf(format string, args ...interface{})  {}
func (l *NoOpLogger) Errorf(format string, args ...interface{}) {}
func (l *NoOpLogger) Fatalf(format string, args ...interface{}) {}

// NormalizeURL normaliza uma URL, adicionando http:// se nenhum esquema estiver presente,
// removendo 'www.' do host e garantindo uma barra no path, se necessário.
func NormalizeURL(rawURL string) (string, error) {
	if !schemePattern.MatchString(rawURL) {
		if protocolRelativePattern.MatchString(rawURL) {
			rawURL = "http:" + rawURL // Adiciona http: para URLs do tipo //example.com
		} else {
			rawURL = "http://" + rawURL // Adiciona http:// como esquema padrão
		}
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	// Remove 'www.' do host se não for o único componente do host
	// (por exemplo, não remover de www.com, mas remover de www.example.com)
	hostParts := strings.Split(parsedURL.Host, ".")
	if len(hostParts) > 1 && strings.ToLower(hostParts[0]) == "www" {
		potentialHost := strings.Join(hostParts[1:], ".")
		// Verifica se remover 'www.' ainda deixaria um host válido (não apenas um TLD ou vazio)
		if potentialHost != "" && strings.Contains(potentialHost, ".") {
			parsedURL.Host = potentialHost
		}
	}

	// Lógica para o path
	if parsedURL.Path == "" {
		// Adiciona uma barra se a URL não for apenas o host e termina com / ou tem query/fragmento
		if parsedURL.RawQuery != "" || parsedURL.Fragment != "" || (strings.HasSuffix(rawURL, "/") && !strings.HasSuffix(parsedURL.String(), "/")) {
			parsedURL.Path = "/"
		}
	} else {
		// Garante que o path comece com uma única barra se não estiver vazio.
		if !strings.HasPrefix(parsedURL.Path, "/") {
			parsedURL.Path = "/" + parsedURL.Path
		}
		// Remove barras finais desnecessárias (ex: /path/ para /path), a menos que seja o root "/"
		if len(parsedURL.Path) > 1 && strings.HasSuffix(parsedURL.Path, "/") {
			parsedURL.Path = strings.TrimRight(parsedURL.Path, "/")
		}
	}

	normalized := parsedURL.String()
	return normalized, nil
}

// ModifyURLQueryParam adiciona ou atualiza um parâmetro de query em uma URL string.
// Retorna a URL modificada ou um erro se a URL original for inválida.
func ModifyURLQueryParam(urlString, paramName, paramValue string) (string, error) {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	query := parsedURL.Query()
	query.Set(paramName, paramValue) // Set irá adicionar se não existir, ou atualizar se existir
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

// ExtractBaseDomain extrai o domínio base de uma URL (e.g., example.com).
// Retorna o domínio base ou um erro se a URL não puder ser parseada ou o domínio não puder ser extraído.
func ExtractBaseDomain(urlString string) (string, error) {
	if !schemePattern.MatchString(urlString) {
		if protocolRelativePattern.MatchString(urlString) {
			urlString = "http:" + urlString
		} else {
			urlString = "http://" + urlString
		}
	}

	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	host := parsedURL.Hostname() // Hostname() remove a porta
	if host == "" {
		return "", &url.Error{Op: "ExtractBaseDomain", URL: urlString, Err: errors.New("host is empty")}
	}

	// Para IPs, retorna o próprio IP como base domain.
	if net.ParseIP(host) != nil {
		return host, nil
	}

	// Para domínios como 'localhost', retorna 'localhost'
	if !strings.Contains(host, ".") {
		return host, nil
	}

	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// Fallback se publicsuffix falhar
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			// Pega os dois últimos componentes como uma heurística simples (ex: example.com de sub.example.com)
			// Isso é uma simplificação e pode não cobrir todos os TLDs complexos corretamente sem publicsuffix.
			return strings.Join(parts[len(parts)-2:], "."), nil
		}
		// Se não for possível determinar de outra forma, retorna o host como está ou um erro.
		// Retornar erro é mais seguro para evitar falsos positivos/negativos.
		return "", fmt.Errorf("failed to get eTLD+1 for host '%s': %w. Original URL: %s", host, err, urlString)
	}
	return eTLDPlusOne, nil
}

// IsSameDomain verifica se duas URLs pertencem ao mesmo domínio base (eTLD+1).
func IsSameDomain(url1String, url2String string) (bool, error) {
	baseDomain1, err1 := ExtractBaseDomain(url1String)
	if err1 != nil {
		return false, fmt.Errorf("error extracting base domain from %s: %v", url1String, err1)
	}
	baseDomain2, err2 := ExtractBaseDomain(url2String)
	if err2 != nil {
		return false, fmt.Errorf("error extracting base domain from %s: %v", url2String, err2)
	}
	return strings.ToLower(baseDomain1) == strings.ToLower(baseDomain2), nil
}

// ExtractParamsFromURL extrai os parâmetros de query de uma URL string e os retorna como um mapa.
// Os valores dos parâmetros são o primeiro valor encontrado para cada chave.
func ExtractParamsFromURL(urlString string) (map[string]string, error) {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return nil, err
	}
	params := make(map[string]string)
	queryValues := parsedURL.Query()
	for key := range queryValues {
		params[key] = queryValues.Get(key) // Get retorna o primeiro valor para a chave
	}
	return params, nil
}

// GetFullURL constrói uma URL completa a partir de um host e um path.
// Assume que o host já contém o esquema. Se não, http:// será prefixado.
// Garante que o path comece com "/".
func GetFullURL(host, path string) string {
	if !schemePattern.MatchString(host) {
		if protocolRelativePattern.MatchString(host) { // ex: //example.com
			host = "http:" + host
		} else { // ex: example.com
			host = "http://" + host
		}
	}

	// Garante que o host não termine com /
	host = strings.TrimRight(host, "/")

	if path == "" {
		path = "/"
	} else if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Tentativa de parse para validar e normalizar
	base, errBase := url.Parse(host)
	if errBase != nil {
		// Se o host base for inválido, retorna a concatenação simples
		return host + path
	}

	ref, errRef := url.Parse(path) // path pode ser absoluto, relativo, ou ter query/fragment
	if errRef != nil {
		// Se o path for inválido, retorna a concatenação simples
		return host + path
	}

	return base.ResolveReference(ref).String()
}

// IsSubdomain verifica se subDomain é um subdomínio de parentDomain.
// Ambos devem ser apenas nomes de host (sem esquema, porta, path).
// Ex: "test.example.com" é subdomínio de "example.com".
// "example.com" não é subdomínio de "example.com".
func IsSubdomain(subDomain, parentDomain string) bool {
	subDomain = strings.ToLower(strings.Trim(subDomain, "."))
	parentDomain = strings.ToLower(strings.Trim(parentDomain, "."))

	if subDomain == parentDomain {
		return false // Um domínio não é subdomínio de si mesmo neste contexto
	}
	return strings.HasSuffix(subDomain, "."+parentDomain)
}

// IsValidURL verifica se uma string é uma URL válida e absoluta.
func IsValidURL(rawURL string) bool {
	parsedURL, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return false
	}
	return parsedURL.Scheme != "" && parsedURL.Host != ""
}

// SanitizeURLString tenta normalizar uma URL. Se falhar, retorna a original.
// Útil para limpar entradas do usuário antes de processamento mais rigoroso.
func SanitizeURLString(rawURL string) string {
	normalized, err := NormalizeURL(rawURL)
	if err != nil {
		return rawURL
	}
	return normalized
}

// GetHostIfURL normaliza a entrada para uma URL e extrai o host.
// Se a entrada não for uma URL válida, retorna a entrada original (assumindo que já seja um host).
func GetHostIfURL(input string) string {
	if !schemePattern.MatchString(input) && !protocolRelativePattern.MatchString(input) {
		// Não parece uma URL, pode ser apenas um host. Mas vamos tentar normalizar e parsear.
		// Se falhar, retornamos o input original.
		normalizedURL, err := NormalizeURL(input)
		if err != nil {
			return input // Falha na normalização, assume que é um host
		}

		parsed, err := url.Parse(normalizedURL)
		if err != nil || parsed.Host == "" {
			return input // Falha no parse ou host vazio, assume que é um host
		}
		return parsed.Host

	}

	// Parece uma URL, normaliza e extrai o host
	normalizedURL, err := NormalizeURL(input)
	if err != nil {
		// Se a normalização falhar para algo que parecia uma URL, retorna o input.
		// Ou podemos tentar um parse direto da input original.
		parsed, errParseOriginal := url.Parse(input)
		if errParseOriginal == nil && parsed.Host != "" {
			return parsed.Host
		}
		return input // Fallback final
	}

	parsed, err := url.Parse(normalizedURL)
	if err != nil || parsed.Host == "" {
		// Se mesmo após a normalização não conseguir parsear ou host for vazio.
		// Tenta parsear a original como último recurso se a original já tinha esquema.
		if schemePattern.MatchString(input) || protocolRelativePattern.MatchString(input) {
			parsedOriginal, errOrig := url.Parse(input)
			if errOrig == nil && parsedOriginal.Host != "" {
				return parsedOriginal.Host
			}
		}
		return input // Fallback
	}
	return parsed.Host
}

// ExtractDomainAndSubdomains extrai o domínio principal e todos os subdomínios de uma URL.
// Ex: "http://foo.bar.example.com/path" -> {"example.com", "bar.example.com", "foo.bar.example.com"}
// Retorna um slice de strings ordenado do domínio mais curto para o mais longo.
func ExtractDomainAndSubdomains(urlString string) ([]string, error) {
	if !schemePattern.MatchString(urlString) && !protocolRelativePattern.MatchString(urlString) {
		urlString = "http://" + urlString
	}

	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL %s: %w", urlString, err)
	}

	host := parsedURL.Hostname()
	if host == "" {
		return nil, fmt.Errorf("host is empty for URL %s", urlString)
	}

	// Lida com IPs diretamente
	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}
	
	// Lida com 'localhost'
	if host == "localhost" {
	    return []string{"localhost"}, nil
	}

	var domains []string
	parts := strings.Split(host, ".")
	if len(parts) < 2 { // Deve ser pelo menos algo como "example.com"
		return []string{host}, nil // Ou retornar erro se não for um TLD reconhecido
	}

	// Tenta obter o eTLD+1 primeiro
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// Se publicsuffix falhar, usa uma heurística simples (pode não ser precisa para todos os TLDs)
		// Pega os dois últimos segmentos se houver pelo menos dois.
		if len(parts) >= 2 {
			eTLDPlusOne = strings.Join(parts[len(parts)-2:], ".")
			domains = append(domains, eTLDPlusOne)
		} else {
			// Se não for possível nem mesmo com a heurística, retorna o host como único domínio.
			// Ou pode-se optar por retornar um erro aqui.
			return []string{host}, fmt.Errorf("could not determine eTLD+1 for '%s' and host has too few parts: %w", host, err)
		}
	} else {
		domains = append(domains, eTLDPlusOne)
	}
	
	// Adiciona subdomínios progressivamente
	// Ex: host = foo.bar.example.com, eTLDPlusOne = example.com
	// parts = [foo, bar, example, com]
	// Se eTLDPlusOne = example.com, seus parts são [example, com] (2)
	// Queremos checar se 'bar.example.com' e 'foo.bar.example.com' são diferentes de eTLDPlusOne e adicioná-los.

	// Encontra o índice onde o eTLD+1 começa no array de 'parts' do host completo
	// Ex: host=a.b.c.com, eTLD+1=c.com. partsHost=[a,b,c,com], partsETLD=[c,com]
	// Queremos iterar a partir de 'b.c.com', depois 'a.b.c.com'
	
	// Se o host atual já é o eTLD+1, não há mais subdomínios para adicionar além dele mesmo.
	if host != eTLDPlusOne {
		// Começa do segundo componente do host (se houver) e vai até o penúltimo antes do eTLD+1
		// Ex: host = a.b.c.example.com, eTLD+1 = example.com
		// parts = [a, b, c, example, com]
		// eTLDPlusOneParts = [example, com]
		// Queremos construir: c.example.com, b.c.example.com, a.b.c.example.com

		// Split eTLDPlusOne para saber quantos componentes ele tem
		eTLDPlusOnePartsCount := len(strings.Split(eTLDPlusOne, "."))

		// O número de componentes de subdomínio é len(parts) - eTLDPlusOnePartsCount
		// Iteramos para construir cada subdomínio progressivo
		// Ex: host = sub2.sub1.domain.com, eTLD+1 = domain.com
		// parts = [sub2, sub1, domain, com]
		// eTLDPlusOnePartsCount = 2
		// Iterar de i = len(parts) - eTLDPlusOnePartsCount - 1  (índice de sub1)  para baixo até 0 (índice de sub2)
		// i = 4 - 2 - 1 = 1 (sub1) -> sub1.domain.com
		// i = 0 (sub2) -> sub2.sub1.domain.com
		for i := len(parts) - eTLDPlusOnePartsCount -1; i >= 0; i-- {
			currentSubdomain := strings.Join(parts[i:], ".")
			if currentSubdomain != eTLDPlusOne { // Evita duplicar se o host for foo.example.com e eTLD+1 for example.com
				// Verifica se já não está na lista para evitar duplicatas de alguma forma estranha
				found := false
				for _, d := range domains {
					if d == currentSubdomain {
						found = true
						break
					}
				}
				if !found {
					domains = append(domains, currentSubdomain)
				}
			}
		}
	}

	// Remove duplicatas e ordena (embora a lógica acima deva evitar duplicatas)
	finalDomains := []string{}
	seen := make(map[string]bool)
	for _, d := range domains {
		if !seen[d] {
			finalDomains = append(finalDomains, d)
			seen[d] = true
		}
	}
	sort.Strings(finalDomains) // Ordena do mais curto para o mais longo (alfabeticamente, que geralmente é por comprimento também)

	return finalDomains, nil
} 