package tlsrouter

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
)

func Listen(addr string) error {
	srv, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	for {
		conn, err := srv.Accept()
		if err != nil {
			log.Printf("Error: %#v", err)
			continue
		}
		go proxy(conn)
	}
}

func proxy(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	tlsConn := tls.Server(conn, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			fmt.Printf("ServerName (SNI): %s\n", hello.ServerName)
			fmt.Printf("SupportedProtos (ALPN): %s\n", hello.SupportedProtos)
			return nil, fmt.Errorf("stop handshake")
		},
	})
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake error: %v", err)
	}
}
