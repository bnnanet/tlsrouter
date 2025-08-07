package tlsrouter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Int52 is a newtype for int that marshals/unmarshals as int64 in JSON.
type Int52 int64

// MarshalJSON implements json.Marshaler.
func (i Int52) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(i), 10)), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (i *Int52) UnmarshalJSON(data []byte) error {
	val, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return err
	}
	*i = Int52(val)
	return nil
}

// Int52Time is a newtype for int64 that marshals/unmarshals a UnixMilli() as ISO Time in JSON.
type Int52Time int64

// MarshalJSON implements json.Marshaler.
func (i Int52Time) MarshalJSON() ([]byte, error) {
	t := time.UnixMilli(int64(i))
	return json.Marshal(t.Format("2006-01-02T15:04:05.000-07:00"))
}

// UnmarshalJSON implements json.Unmarshaler.
func (i *Int52Time) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	*i = Int52Time(t.UnixMilli())
	return nil
}

// JSONTime is a newtype for int64 that marshals/unmarshals a UnixMilli() as ISO Time in JSON.
type JSONTime time.Time

// MarshalJSON implements json.Marshaler.
func (t JSONTime) MarshalJSON() ([]byte, error) {
	then := time.Time(t)
	isoTime := then.Format("2006-01-02T15:04:05.000-07:00")
	return json.Marshal(isoTime)
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *JSONTime) UnmarshalJSON(data []byte) error {
	var isoTime string
	if err := json.Unmarshal(data, &isoTime); err != nil {
		return err
	}
	then, err := time.Parse(time.RFC3339, isoTime)
	if err != nil {
		return err
	}
	*t = JSONTime(then)
	return nil
}

type PConn struct {
	Self         bool      `json:"self,omitempty"`
	Address      string    `json:"address"`
	ServerName   string    `json:"servername"`
	ALPN         string    `json:"alpn"`
	Read         Int52     `json:"read"`
	Written      Int52     `json:"written"`
	Since        JSONTime  `json:"since"`
	PlainRead    Int52     `json:"plain_read"`
	PlainWritten Int52     `json:"plain_written"`
	LastRead     Int52Time `json:"last_read"`
	LastWrite    Int52Time `json:"last_write"`
}

func WConnToPConn(wconn *wrappedConn) PConn {
	pconn := PConn{
		Address:    wconn.Conn.RemoteAddr().String(),
		ServerName: wconn.SNIALPN.SNI(),
		ALPN:       wconn.SNIALPN.ALPN(),
		Read:       Int52(wconn.BytesRead.Load()),
		Written:    Int52(wconn.BytesWritten.Load()),
		LastRead:   Int52Time(wconn.LastRead.Load()),
		LastWrite:  Int52Time(wconn.LastWrite.Load()),
		Since:      JSONTime(wconn.Connected),
	}
	if wconn.PlainConn != nil {
		tlsState := wconn.PlainConn.ConnectionState()
		pconn.ServerName = tlsState.ServerName
		pconn.ALPN = tlsState.NegotiatedProtocol
		pconn.PlainRead = Int52(wconn.PlainConn.BytesRead.Load())
		pconn.PlainWritten = Int52(wconn.PlainConn.BytesWritten.Load())
	}
	return pconn
}

func (c *Config) requireToken(w http.ResponseWriter, r *http.Request) bool {
	username, password, ok := r.BasicAuth()

	adminToken := c.TabVault.Get(c.AdminDNS.AdminToken)
	p := BasicAuthPassword(adminToken)
	if !ok || !p.Verify(username, password) {
		jsonError(w, http.StatusUnauthorized, "unauthorized", "Unauthorized", "Invalid credentials")
		return false
	}
	return true
}

func (lc *ListenConfig) RouteGetConfig(w http.ResponseWriter, r *http.Request) {
	lc.newMu.Lock()
	defer lc.newMu.Unlock()

	curConf := lc.LoadConfig()
	if ok := curConf.requireToken(w, r); !ok {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(curConf)
}

func (lc *ListenConfig) RouteGetNewConfig(w http.ResponseWriter, r *http.Request) {
	lc.newMu.Lock()
	defer lc.newMu.Unlock()

	curConf := lc.LoadConfig()
	if ok := curConf.requireToken(w, r); !ok {
		return
	}

	newConf := lc.newConfig.Load()
	if newConf == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(newConf)

}

type ConfigConflict struct {
	Hash     string `json:"hash"`
	Revision string `json:"rev"`
}

type ConfigError struct {
	Error string `json:"error"`
}

func (lc *ListenConfig) RouteSetNewConfig(w http.ResponseWriter, r *http.Request) {
	lc.newMu.Lock()
	defer lc.newMu.Unlock()

	curConf := lc.LoadConfig()
	if ok := curConf.requireToken(w, r); !ok {
		return
	}

	w.Header().Set("Content-Type", "application/json")

	newConf := lc.newConfig.Load()
	if newConf == nil {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(nil)
		return
	}

	hashOrRev := r.PathValue("HashOrRev")
	if newConf.Hash != hashOrRev && newConf.Revision != hashOrRev {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(&ConfigConflict{
			Hash:     newConf.Hash,
			Revision: newConf.Revision,
		})
		return
	}

	if curConf.Hash == newConf.Hash {
		w.WriteHeader(http.StatusNotModified)
		_ = json.NewEncoder(w).Encode(nil)
		return
	}

	newConf.FilePath = curConf.FilePath
	if err := newConf.Save(); err != nil {
		// TODO panic
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ConfigError{
			Error: "failed to save config",
		})
		return
	}
	info, err := os.Stat(newConf.FilePath)
	if err != nil {
		// TODO panic
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ConfigError{
			Error: "config file disappeared",
		})
		return
	}
	newConf.FileTime = info.ModTime()

	// TODO XXXX TODO
	// actually we need to regen and replace all the config stuff
	// (because we don't have idle detection for ssh, postgresql, smb, etc
	// and using the old config will eventually lead to strange bad gateway errors)
	curConf.Reincarnate()

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(&curConf)
}

// APIService defines a rule for matching domains and ALPNs to backends.
type APIService struct {
	AppSlug      string   `json:"app_slug"`
	Slug         string   `json:"slug"`
	Comment      *string  `json:"comment,omitempty"`
	Disabled     *bool    `json:"disabled,omitempty"`
	Domains      []string `json:"domains"`
	ALPNs        []string `json:"alpns"`
	BackendSlugs []string `json:"backend_slugs,omitempty"`
}

func (lc *ListenConfig) RouteListServices(w http.ResponseWriter, r *http.Request) {
	lc.newMu.Lock()
	defer lc.newMu.Unlock()

	curConf := lc.LoadConfig()
	if ok := curConf.requireToken(w, r); !ok {
		return
	}

	newConf := lc.newConfig.Load()
	if newConf == nil {
		newConf = &curConf
	}
	services := []APIService{}

	var domains []string
	domainList := r.URL.Query().Get("domains")
	domainList = strings.TrimSpace(domainList)
	if len(domainList) > 0 {
		domains = strings.FieldsFunc(domainList, func(r rune) bool {
			return r == ' ' || r == ','
		})
		for i, domain := range domains {
			domains[i] = strings.TrimSpace(domain)
		}
	}

	var alpns []string
	alpnList := r.URL.Query().Get("alpns")
	alpnList = strings.TrimSpace(alpnList)
	if len(alpnList) > 0 {
		alpns = strings.FieldsFunc(alpnList, func(r rune) bool {
			return r == ' ' || r == ','
		})
		for i, alpn := range alpns {
			alpns[i] = strings.TrimSpace(alpn)
		}
	}

	for _, app := range newConf.Apps {
		for _, srv := range app.Services {
			var backendSlugs []string
			for _, be := range srv.Backends {
				backendSlugs = append(backendSlugs, be.Slug)
			}
			service := APIService{
				AppSlug:      app.Slug,
				Slug:         srv.Slug,
				Comment:      &srv.Comment,
				Disabled:     &srv.Disabled,
				Domains:      srv.Domains,
				ALPNs:        srv.ALPNs,
				BackendSlugs: backendSlugs,
			}

			var keepByDomain bool
			if len(domains) == 0 {
				keepByDomain = true
			}
			for _, domain := range domains {
				for _, d := range srv.Domains {
					if strings.HasPrefix(domain, ".") && strings.HasSuffix(d, domain) {
						keepByDomain = true
						break
					}
					if slices.Contains(srv.Domains, domain) {
						keepByDomain = true
						break
					}
				}
				if keepByDomain {
					break
				}
			}

			var keepByALPN bool
			if len(alpns) == 0 {
				keepByALPN = true
			}
			for _, alpn := range alpns {
				for _, p := range srv.ALPNs {
					if strings.HasPrefix(alpn, ".") && strings.HasSuffix(p, alpn) {
						keepByALPN = true
						break
					}
					if slices.Contains(srv.ALPNs, alpn) {
						keepByALPN = true
						break
					}
				}
				if keepByALPN {
					break
				}
			}

			if keepByDomain && keepByALPN {
				services = append(services, service)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(services)
}

func (lc *ListenConfig) RouteSetService(w http.ResponseWriter, r *http.Request) {
	lc.newMu.Lock()
	defer lc.newMu.Unlock()

	curConf := lc.LoadConfig()
	if ok := curConf.requireToken(w, r); !ok {
		return
	}

	newConf := lc.newConfig.Load()
	if newConf == nil {
		// Ooopsies! We're not supposed to make a copy of this!!!
		newConfVal := lc.LoadConfig()
		rev, err := strconv.Atoi(newConfVal.Revision)
		if err == nil {
			rev++
			newConfVal.Revision = strconv.Itoa(rev)
		}
		newConf = &newConfVal
	}

	var apiSrv APIService
	dec := json.NewDecoder(r.Body)
	defer func() {
		_ = r.Body.Close()
	}()

	if err := dec.Decode(&apiSrv); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotAcceptable)
		_ = json.NewEncoder(w).Encode(ConfigError{
			Error: "could not parse json input",
		})
		return
	}

	// TODO Disabled, Comments nil
	// TODO Backends from Slugs
	srv := ConfigService{
		Domains:        apiSrv.Domains,
		ALPNs:          apiSrv.ALPNs,
		Backends:       make([]Backend, 0),
		CurrentBackend: new(atomic.Uint32),
	}
	if apiSrv.Comment != nil {
		srv.Comment = *apiSrv.Comment
	}
	if apiSrv.Disabled != nil {
		srv.Disabled = *apiSrv.Disabled
	}
	srv.Slug = srv.GenSlug()
	apiSrv.Slug = srv.Slug

	for i, app := range newConf.Apps {
		if app.Slug != apiSrv.AppSlug {
			for _, other := range app.Services {
				if other.Slug == srv.Slug {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					_ = json.NewEncoder(w).Encode(ConfigError{
						Error: fmt.Sprintf("service slug '%s' conflicts with existing service in app '%s'", srv.Slug, app.Slug),
					})
					return
				}
			}
			continue
		}

		var found bool
		for i, existing := range app.Services {
			if existing.Slug != srv.Slug {
				continue
			}
			found = true

			if apiSrv.Comment == nil {
				srv.Comment = app.Services[i].Comment
			}
			if apiSrv.Disabled == nil {
				srv.Disabled = app.Services[i].Disabled
			}

			if len(apiSrv.BackendSlugs) > 0 {
				for _, slug := range apiSrv.BackendSlugs {
					// TODO add or replace
					// { backends: [
					//     slug, address, port, terminate_tls, connect_tls, connect_skip_verify
					// ] }
					backend := findBackendBySlug(newConf, slug)
					if backend == nil {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusBadRequest)
						_ = json.NewEncoder(w).Encode(ConfigError{
							Error: fmt.Sprintf("backend slug '%s' not found", slug),
						})
						return
					}
					srv.Backends = append(srv.Backends, *backend)
				}
			} else {
				srv.Backends = existing.Backends
			}

			app.Services[i] = srv
			break
		}

		if !found {
			for _, slug := range apiSrv.BackendSlugs {
				backend := findBackendBySlug(newConf, slug)
				if backend == nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(ConfigError{
						Error: fmt.Sprintf("backend slug '%s' not found", slug),
					})
					return
				}
				srv.Backends = append(srv.Backends, *backend)
			}
			app.Services = append(app.Services, srv)
		}

		newConf.Apps[i] = app
	}

	newConf.Hash = newConf.ShortSHA2()
	lc.newConfig.Store(newConf)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(newConf)
}

// findBackendBySlug searches for a backend by slug across all apps
func findBackendBySlug(conf *Config, slug string) *Backend {
	for _, app := range conf.Apps {
		for _, svc := range app.Services {
			for _, backend := range svc.Backends {
				if backend.Slug == slug {
					return &backend
				}
			}
		}
	}
	return nil
}

func (lc *ListenConfig) RouteListConnections(w http.ResponseWriter, r *http.Request) {
	lc.newMu.Lock() // not necessary for listing conns, just for consistency
	defer lc.newMu.Unlock()

	curConf := lc.LoadConfig()
	if ok := curConf.requireToken(w, r); !ok {
		return
	}

	list := []PConn{}

	lc.Conns.Range(func(_, v any) bool {
		wconn := v.(*wrappedConn)
		pconn := WConnToPConn(wconn)
		if pconn.Address == r.RemoteAddr {
			pconn.Self = true
		}
		list = append(list, pconn)
		return true
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(list)
}

func (lc *ListenConfig) RouteCloseRemotes(w http.ResponseWriter, r *http.Request) {
	lc.newMu.Lock() // not necessary for closing remotes, just for consistency
	defer lc.newMu.Unlock()

	curConf := lc.LoadConfig()
	if ok := curConf.requireToken(w, r); !ok {
		return
	}

	var selfToClose *wrappedConn
	list := []PConn{}

	remoteAddr := r.PathValue("RemoteAddr")
	lc.Conns.Range(func(_, v any) bool {
		wconn := v.(*wrappedConn)
		hostport := wconn.Conn.RemoteAddr().String()
		if remoteAddr == hostport || strings.HasPrefix(hostport, remoteAddr+":") {
			pconn := WConnToPConn(wconn)
			if pconn.Address == r.RemoteAddr {
				pconn.Self = true
				selfToClose = wconn
			} else {
				_ = wconn.Conn.Close()
			}
			list = append(list, pconn)
			if remoteAddr == hostport {
				return false
			}
		}
		return true
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(list)

	go func() {
		time.Sleep(1 * time.Millisecond)
		if selfToClose != nil {
			_ = selfToClose.Close()
		}
	}()
}

func (lc *ListenConfig) RouteCloseClients(w http.ResponseWriter, r *http.Request) {
	lc.newMu.Lock() // not necessary for closing clients, just for consistency
	defer lc.newMu.Unlock()

	curConf := lc.LoadConfig()
	if ok := curConf.requireToken(w, r); !ok {
		return
	}

	snialpn := r.PathValue("Service")
	fmt.Println("SNIALPN Query", snialpn)
	list, selfToClose := lc.closeClients(snialpn, r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(list)

	go func() {
		time.Sleep(1 * time.Millisecond)
		if selfToClose != nil {
			_ = selfToClose.Close()
		}
	}()
}

func (lc *ListenConfig) closeClients(snialpn string, remoteAddr string) ([]PConn, *wrappedConn) {
	var selfToClose *wrappedConn
	list := []PConn{}

	lc.Conns.Range(func(_, v any) bool {
		wconn := v.(*wrappedConn)
		fmt.Println("SNIALPN", wconn.SNIALPN.SNI())
		if snialpn == wconn.SNIALPN.SNI() || snialpn == string(wconn.SNIALPN) {
			pconn := WConnToPConn(wconn)
			if pconn.Address == remoteAddr {
				pconn.Self = true
				selfToClose = wconn
			} else {
				_ = wconn.Conn.Close()
			}
			list = append(list, pconn)
			if snialpn == string(wconn.SNIALPN) {
				return false
			}
		}
		return true
	})

	return list, selfToClose
}
