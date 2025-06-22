package tlsrouter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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

func (lc *ListenConfig) GetConfig(w http.ResponseWriter, r *http.Request) {
	_ = lc.config.ShortSHA2() // ensure current hash will be present

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(lc.config)
}

func (lc *ListenConfig) ListConnections(w http.ResponseWriter, r *http.Request) {
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

func (lc *ListenConfig) CloseRemotes(w http.ResponseWriter, r *http.Request) {
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

func (lc *ListenConfig) CloseClients(w http.ResponseWriter, r *http.Request) {
	var selfToClose *wrappedConn
	list := []PConn{}

	snialpn := r.PathValue("Service")
	fmt.Println("SNIALPN Query", snialpn)
	lc.Conns.Range(func(_, v any) bool {
		wconn := v.(*wrappedConn)
		fmt.Println("SNIALPN", wconn.SNIALPN.SNI())
		if snialpn == wconn.SNIALPN.SNI() || snialpn == string(wconn.SNIALPN) {
			pconn := WConnToPConn(wconn)
			if pconn.Address == r.RemoteAddr {
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
