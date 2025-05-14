package tlsrouter

import "net"

func Listen(addr string) error {
	srv, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	for {
		conn, err := srv.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}
}
