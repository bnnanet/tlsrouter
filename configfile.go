package tlsrouter

import (
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
)

func NormalizeConfig(conf *Config) (map[string][]string, map[SNIALPN]*ConfigService) {
	domainALPNMatchers := map[string][]string{}
	snialpnMatchers := map[SNIALPN]*ConfigService{}

	for i, app := range conf.Apps {
		for i, srv := range app.Services {
			if len(srv.Backends) == 0 {
				fmt.Println("debug: warn: service has no backends")
				continue
			}

			if len(srv.Domains) == 0 {
				fmt.Println("debug: warn: service has no domains")
				continue
			}

			if len(srv.ALPNs) == 0 {
				srv.ALPNs = append(srv.ALPNs, "http/1.1")
			}

			if len(srv.Slug) == 0 {
				// TODO make sure this doesn't conflict with other slugs
				srv.Slug = srv.GenSlug()
			}

			for i, be := range srv.Backends {
				if len(be.Slug) == 0 {
					addr := strings.ReplaceAll(be.Address, ".", "-")
					addr = strings.ReplaceAll(addr, ":", "-")
					addr = strings.ReplaceAll(addr, "--", "-")
					// TODO make sure this doesn't conflict with other slugs
					be.Slug = addr + "--" + fmt.Sprintf("%d", be.Port)
				}
				srv.Backends[i] = be
			}

			for _, domain := range srv.Domains {
				// Example.com => example.com
				domain = strings.ToLower(domain)

				// *.example.com => .example.com
				domain = strings.TrimPrefix(domain, "*")

				alpns := domainALPNMatchers[domain]
				for _, alpn := range srv.ALPNs {
					if !slices.Contains(alpns, alpn) {
						alpns = append(alpns, alpn)
						domainALPNMatchers[domain] = alpns
					}

					snialpn := NewSNIALPN(domain, alpn)

					tlsMatch := snialpnMatchers[snialpn]
					if tlsMatch == nil {
						tlsMatch = &ConfigService{
							CurrentBackend: new(atomic.Uint32),
						}
						snialpnMatchers[snialpn] = tlsMatch
					}

					for _, b := range srv.Backends {
						// fmt.Printf("\n\nDEBUG: m.Backends[i] %#v\n", b)
						b.Host = fmt.Sprintf("%s:%d", b.Address, b.Port)
						tlsMatch.Backends = append(tlsMatch.Backends, b)
					}
				}
			}
			app.Services[i] = srv
		}

		for i, dnsConf := range app.DNSProviders {
			if len(dnsConf.APIToken) == 0 {
				continue
			}

			var err error
			dnsConf.APIToken, err = conf.TabVault.ToVaultURI(dnsConf.APIToken)
			if err != nil {
				panic("TabVault could not be written to")
			}

			app.DNSProviders[i] = dnsConf
		}

		conf.Apps[i] = app
	}

	return domainALPNMatchers, snialpnMatchers
}

func LintConfig(conf *Config, allowedAlpns []string) error {
	if len(conf.AdminDNS.Domains) == 0 {
		return fmt.Errorf("error: 'admin.domains' is empty")
	}

	for _, domain := range conf.AdminDNS.Domains {
		d := strings.ToLower(domain)

		if domain != d {
			return fmt.Errorf("lint: domain is not lowercase: %q", domain)
		}
	}

	var hasActiveService bool
	for _, app := range conf.Apps {
		if app.Disabled {
			continue
		}
		for _, srv := range app.Services {
			if srv.Disabled {
				continue
			}
			hasActiveService = true
			break
		}
		if hasActiveService {
			break
		}
	}
	if !hasActiveService {
		// TODO once we can edit the config via API, this is not a problem
		return fmt.Errorf("error: no 'apps' with active (non-disabled) 'services'")
	}

	for _, app := range conf.Apps {
		for _, srv := range app.Services {
			snialpns := strings.Join(srv.Domains, ",") + "; " + strings.Join(srv.ALPNs, ",")

			for _, domain := range srv.Domains {
				d := strings.ToLower(domain)

				if domain != d {
					return fmt.Errorf("lint: domain is not lowercase: %q", domain)
				}

				if strings.HasPrefix(domain, "*") {
					if !strings.HasPrefix(domain, "*.") {
						return fmt.Errorf("lint: invalid use of wildcard %q (must be '*.')", domain)
					}
				}
			}

			if len(allowedAlpns) > 0 {
				for _, alpn := range srv.ALPNs {
					if !slices.Contains(allowedAlpns, alpn) {
						if alpn != "*" {
							return fmt.Errorf("lint: unknown alpn %q", alpn)
						}
					}
				}
			}

			if len(srv.ALPNs) == 0 {
				return fmt.Errorf("domains set %q have no 'alpns' defined", snialpns)
			}

			if len(srv.Backends) == 0 {
				fmt.Fprintf(os.Stderr, "warn: domains+alpns set %q have no 'backends' defined\n", snialpns)
			}

			for i, b := range srv.Backends {
				if b.Address == "" {
					return fmt.Errorf("target %d in set %q has empty 'address'", i, snialpns)
				}
				if b.Port == 0 {
					return fmt.Errorf("target %d in set %q has empty 'port'", i, snialpns)
				}
			}
		}
	}

	return nil
}

var expectedHeaders = []string{
	"app_slug",
	"domain",
	"alpn",
	"backend_address",
	"backend_port",
	"terminate_tls",
	"connect_tls",
	"skip_tls_verify",
	"allowed_client_hostnames",
}

func ReadCSVToConfig(r *csv.Reader) (*Config, error) {
	config := &Config{
		AdminDNS: ConfigAdmin{},
		Apps:     []ConfigApp{},
	}
	appMap := make(map[string]*ConfigApp)
	appServicesMap := make(map[string][]*ConfigService)
	serviceMap := make(map[string]*ConfigService)

	// Read header
	headers, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("expected 'header' to be valid, got error: %q", err)
	}

	// Map header names to indices
	headerIndices := make(map[string]int)
	for _, header := range expectedHeaders {
		for i, h := range headers {
			if h == header {
				headerIndices[header] = i
				break
			}
		}
	}

	apps := []*ConfigApp{}
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("expected 'record' to be valid, got error: %q", err)
		}

		// Extract fields, using empty defaults for missing columns
		appSlug := ""
		if i, ok := headerIndices["app_slug"]; ok && i < len(record) {
			appSlug = record[i]
		}
		domain := ""
		if i, ok := headerIndices["domain"]; ok && i < len(record) {
			domain = record[i]
		}
		alpn := ""
		if i, ok := headerIndices["alpn"]; ok && i < len(record) {
			alpn = record[i]
		}
		backendAddress := ""
		if i, ok := headerIndices["backend_address"]; ok && i < len(record) {
			backendAddress = record[i]
		}
		backendPortStr := ""
		if i, ok := headerIndices["backend_port"]; ok && i < len(record) {
			backendPortStr = record[i]
		}
		terminateTLS := false
		if i, ok := headerIndices["terminate_tls"]; ok && i < len(record) && record[i] == "true" {
			terminateTLS = true
		}
		connectTLS := false
		if i, ok := headerIndices["connect_tls"]; ok && i < len(record) && record[i] == "true" {
			connectTLS = true
		}
		connectInsecure := false
		if i, ok := headerIndices["connect_insecure"]; ok && i < len(record) && record[i] == "true" {
			connectInsecure = true
		}
		allowedClientHostnames := []string{}
		if i, ok := headerIndices["allowed_client_hostnames"]; ok && i < len(record) && record[i] != "" {
			allowedClientHostnames = strings.Split(record[i], ",")
		}

		// handle the special case of the admin app
		if appSlug == "_admin" && len(domain) > 0 {
			config.AdminDNS.Domains = append(config.AdminDNS.Domains, domain)

			if len(alpn) > 0 {
				config.AdminDNS.AdminUser = alpn
			}
			if len(config.AdminDNS.AdminUser) == 0 {
				config.AdminDNS.AdminUser = "admin"
			}

			if len(backendAddress) > 0 {
				config.AdminDNS.AdminToken = backendAddress
			}
			if len(config.AdminDNS.AdminToken) == 0 {
				config.AdminDNS.AdminToken = mustGenHex16()
			}

			continue
		}

		// Convert backend port to uint16
		var port uint16
		if backendPortStr != "" {
			portVal, err := strconv.ParseUint(backendPortStr, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid 'backend_port': %v", err)
			}
			port = uint16(portVal)
		}

		// Skip empty rows
		if appSlug == "" && domain == "" && alpn == "" && backendAddress == "" && backendPortStr == "" {
			continue
		}

		// Get or create app
		app, exists := appMap[appSlug]
		if !exists && appSlug != "" {
			app = &ConfigApp{
				Slug:     appSlug,
				Services: []ConfigService{},
			}
			appMap[app.Slug] = app
			apps = append(apps, app)
		}

		appServices, exists := appServicesMap[app.Slug]
		if !exists && appSlug != "" {
			appServices = []*ConfigService{}
		}

		// Skip if no appSlug or domain or alpn
		if appSlug == "" || domain == "" || alpn == "" {
			continue
		}

		// Generate service slug
		serviceSlug := strings.ReplaceAll(domain, ".", "-")
		if strings.HasPrefix(serviceSlug, "-") {
			serviceSlug = "wild-" + serviceSlug
		}
		serviceAlpn := alpn
		if slices.Contains([]string{"http/1.1", "h2", "h3"}, alpn) {
			serviceAlpn = "http"
		}
		serviceAlpn = strings.Split(serviceAlpn, "/")[0]
		serviceSlug = serviceSlug + "-" + serviceAlpn

		// Get or create service
		service, exists := serviceMap[serviceSlug]
		if !exists {
			service = &ConfigService{
				Slug:                   serviceSlug,
				Domains:                []string{domain},
				ALPNs:                  []string{alpn},
				Backends:               []Backend{},
				AllowedClientHostnames: allowedClientHostnames,
			}
			serviceMap[serviceSlug] = service
			// app.Services = append(app.Services, *service)
		} else {
			// Ensure domain and ALPN are added if not present
			if !slices.Contains(service.Domains, domain) {
				service.Domains = append(service.Domains, domain)
			}
			if !slices.Contains(service.ALPNs, alpn) {
				service.ALPNs = append(service.ALPNs, alpn)
			}
			// Merge allowed_client_hostnames, avoiding duplicates
			for _, hostname := range allowedClientHostnames {
				if !slices.Contains(service.AllowedClientHostnames, hostname) && hostname != "" {
					service.AllowedClientHostnames = append(service.AllowedClientHostnames, hostname)
				}
			}
		}

		// Generate backend slug
		backendSlug := ""
		if backendAddress != "" && backendPortStr != "" {
			backendSlug = fmt.Sprintf("%s--%d", backendAddress, port)
		}

		// Create backend if address and port are provided
		if backendSlug != "" {
			backend := Backend{
				Slug:          backendSlug,
				Address:       backendAddress,
				Port:          port,
				TerminateTLS:  terminateTLS,
				ConnectTLS:    connectTLS,
				SkipTLSVerify: connectInsecure,
			}
			service.Backends = append(service.Backends, backend)
		}
		appServices = append(appServices, service)
		appServicesMap[app.Slug] = appServices
	}
	for _, app := range apps {
		services := appServicesMap[app.Slug]
		for _, service := range services {
			app.Services = append(app.Services, *service)
		}
		config.Apps = append(config.Apps, *app)
	}

	return config, nil
}

func mustGenHex16() string {
	bytes := make([]byte, 8)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}

	hexStr := hex.EncodeToString(bytes)
	formatted := fmt.Sprintf("%s-%s-%s-%s", hexStr[:4], hexStr[4:8], hexStr[8:12], hexStr[12:])
	return formatted
}

// CSVRecord represents a single row in the CSV output.
type CSVRecord struct {
	AppSlug                string
	Domain                 string
	ALPN                   string
	BackendAddress         string
	BackendPort            uint16
	TerminateTLS           bool
	ConnectTLS             bool
	SkipTLSVerify          bool
	AllowedClientHostnames string
}

// ToCSV converts the config to a CSV string, using ToRecords and RecordsToCSV.
func (c *Config) ToCSV(w io.Writer) error {
	records, err := c.ToRecords()
	if err != nil {
		return fmt.Errorf("failed to generate CSV records: %w", err)
	}

	csvw := csv.NewWriter(w)
	return RecordsToCSV(csvw, records)
}

// ToRecords creates a sorted list of CSV records from the config.
func (c *Config) ToRecords() ([]CSVRecord, error) {
	var records []CSVRecord
	for _, app := range c.Apps {
		for _, service := range app.Services {
			for _, backend := range service.Backends {
				for _, domain := range service.Domains {
					for _, alpn := range service.ALPNs {
						records = append(records, CSVRecord{
							AppSlug:                app.Slug,
							Domain:                 domain,
							ALPN:                   alpn,
							BackendAddress:         backend.Address,
							BackendPort:            backend.Port,
							TerminateTLS:           backend.TerminateTLS,
							ConnectTLS:             backend.ConnectTLS,
							SkipTLSVerify:          backend.SkipTLSVerify,
							AllowedClientHostnames: strings.Join(service.AllowedClientHostnames, ";"),
						})
					}
				}
			}
		}
	}

	// TODO sort before iterating
	// Sort records for deterministic order
	slices.SortFunc(records, func(a, b CSVRecord) int {
		if a.AppSlug != b.AppSlug {
			return strings.Compare(a.AppSlug, b.AppSlug)
		}
		if a.Domain != b.Domain {
			return strings.Compare(a.Domain, b.Domain)
		}
		if a.ALPN != b.ALPN {
			return strings.Compare(a.ALPN, b.ALPN)
		}
		if a.BackendAddress != b.BackendAddress {
			return strings.Compare(a.BackendAddress, b.BackendAddress)
		}
		if a.BackendPort != b.BackendPort {
			if a.BackendPort < b.BackendPort {
				return -1
			}
			if a.BackendPort > b.BackendPort {
				return 1
			}
		}
		if a.TerminateTLS != b.TerminateTLS {
			return strings.Compare(fmt.Sprintf("%t", a.TerminateTLS), fmt.Sprintf("%t", b.TerminateTLS))
		}
		if a.ConnectTLS != b.ConnectTLS {
			return strings.Compare(fmt.Sprintf("%t", a.ConnectTLS), fmt.Sprintf("%t", b.ConnectTLS))
		}
		if a.SkipTLSVerify != b.SkipTLSVerify {
			return strings.Compare(fmt.Sprintf("%t", a.SkipTLSVerify), fmt.Sprintf("%t", b.SkipTLSVerify))
		}
		return strings.Compare(a.AllowedClientHostnames, b.AllowedClientHostnames)
	})

	return records, nil
}

// RecordsToCSV serializes a list of CSV records to a CSV string.
func RecordsToCSV(csvw *csv.Writer, records []CSVRecord) error {
	// Write CSV header
	if err := csvw.Write(expectedHeaders); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write records
	for _, record := range records {
		csvRow := []string{
			record.AppSlug,
			record.Domain,
			record.ALPN,
			record.BackendAddress,
			fmt.Sprintf("%d", record.BackendPort),
			fmt.Sprintf("%t", record.TerminateTLS),
			fmt.Sprintf("%t", record.ConnectTLS),
			fmt.Sprintf("%t", record.SkipTLSVerify),
			record.AllowedClientHostnames,
		}
		if err := csvw.Write(csvRow); err != nil {
			return fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	csvw.Flush()
	if err := csvw.Error(); err != nil {
		return fmt.Errorf("failed to flush CSV writer: %w", err)
	}

	return nil
}
