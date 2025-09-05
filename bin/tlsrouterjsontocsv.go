package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Backend struct {
	Slug            string `json:"slug"`
	Address         string `json:"address"`
	Port            int    `json:"port"`
	TerminateTLS    bool   `json:"terminate_tls"`
	ConnectTLS      bool   `json:"connect_tls"`
	ConnectInsecure bool   `json:"connect_insecure"`
}

type Service struct {
	Slug     string    `json:"slug"`
	Domains  []string  `json:"domains"`
	Alpns    []string  `json:"alpns"`
	Backends []Backend `json:"backends"`
}

type App struct {
	Slug     string    `json:"slug"`
	Services []Service `json:"services"`
}

type Data struct {
	Apps []App `json:"apps"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <json-file>\n", os.Args[0])
		os.Exit(1)
	}

	file, _ := os.Open(os.Args[1])
	defer func() { _ = file.Close() }()

	bytes, _ := io.ReadAll(file)

	var data Data
	_ = json.Unmarshal(bytes, &data)

	fmt.Println("app_slug\tdomain\talpn\tbackend_address\tbackend_port\tterminate_tls\tconnect_tls\tconnect_insecure")

	for _, app := range data.Apps {
		for _, service := range app.Services {
			for _, domain := range service.Domains {
				for _, alpn := range service.Alpns {
					for _, backend := range service.Backends {
						fmt.Printf("%s\t%s\t%s\t%s\t%d\t%v\t%v\t%v\n",
							app.Slug, domain, alpn,
							backend.Address, backend.Port,
							backend.TerminateTLS, backend.ConnectTLS, backend.ConnectInsecure)
					}
				}
			}
		}
	}
}
