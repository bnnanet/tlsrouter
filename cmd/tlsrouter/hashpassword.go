package main

import (
	"bufio"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func readPasswordPrompt(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	cmd := exec.Command("stty", "-echo")
	cmd.Stdin = os.Stdin
	_ = cmd.Run()
	defer func() {
		cmd := exec.Command("stty", "echo")
		cmd.Stdin = os.Stdin
		_ = cmd.Run()
		fmt.Fprintln(os.Stderr)
	}()

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return "", fmt.Errorf("no input")
	}
	return scanner.Text(), nil
}

func runHashPassword() int {
	var password string

	fi, _ := os.Stdin.Stat()
	isTTY := fi.Mode()&(os.ModeDevice|os.ModeCharDevice) == os.ModeDevice|os.ModeCharDevice

	if !isTTY {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			fmt.Fprintln(os.Stderr, "Error: no input")
			return 1
		}
		password = strings.TrimSpace(scanner.Text())
	} else {
		pw1, err := readPasswordPrompt("Enter password: ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}

		pw2, err := readPasswordPrompt("Confirm password: ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}

		if pw1 != pw2 {
			fmt.Fprintln(os.Stderr, "Error: passwords do not match")
			return 1
		}
		password = pw1
	}

	if len(password) == 0 {
		fmt.Fprintln(os.Stderr, "Error: empty password")
		return 1
	}

	salt := make([]byte, 16)
	_, _ = rand.Read(salt)

	iterations := 600000
	dk, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	fmt.Printf("$pbkdf2-sha256$%d$%s$%s\n",
		iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk),
	)
	return 0
}
