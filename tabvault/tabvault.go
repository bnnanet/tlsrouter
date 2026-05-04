package tabvault

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
)

const phcPrefix = "$pbkdf2-sha256$"

type SecretID = string
type SecretHash = [32]byte
type SecretValue = string

func hashSecret(secret string) SecretHash {
	return sha256.Sum256([]byte(secret))
}

type TabVault struct {
	secrets  map[SecretID]SecretValue
	hashes   map[SecretHash]SecretID
	mu       sync.RWMutex
	filepath string
}

func OpenOrCreate(filepath string) (*TabVault, error) {
	v := &TabVault{
		secrets:  make(map[SecretID]SecretValue),
		hashes:   make(map[SecretHash]SecretID),
		filepath: filepath,
	}

	// Check if file exists, create with header if not
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		file, err := os.Create(filepath)
		if err != nil {
			return nil, err
		}
		writer := csv.NewWriter(file)
		writer.Comma = '\t'
		_ = writer.Write([]string{"vault_id", "vault_secret"})
		writer.Flush()

		if err := file.Close(); err != nil {
			return nil, err
		}
	}

	// Read existing secrets
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	reader := csv.NewReader(file)
	reader.Comma = '\t'
	reader.FieldsPerRecord = 2
	reader.TrimLeadingSpace = true

	// Skip header
	_, err = reader.Read()
	if err != nil {
		return nil, err
	}

	// Read records
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	for _, record := range records {
		id := record[0]
		secret := record[1]
		v.secrets[id] = secret
		v.hashes[hashSecret(secret)] = id
	}
	return v, nil
}

func (v *TabVault) ToVaultURI(s string) (string, error) {
	if strings.HasPrefix(s, "vault://") {
		return s, nil
	}

	id, err := v.Add(s)
	if err != nil {
		return "", err
	}
	return "vault://" + id, nil
}

func (v *TabVault) Add(secret string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	hash := hashSecret(secret)
	if id, exists := v.hashes[hash]; exists {
		return id, nil
	}

	idBytes := make([]byte, 16)
	_, _ = rand.Read(idBytes)
	id := hex.EncodeToString(idBytes)

	v.secrets[id] = secret
	v.hashes[hash] = id

	file, err := os.OpenFile(v.filepath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return "", err
	}

	writer := csv.NewWriter(file)
	writer.Comma = '\t'
	if err := writer.Write([]string{id, secret}); err != nil {
		return "", err
	}
	writer.Flush()

	if err := file.Sync(); err != nil {
		return "", err
	}
	return id, file.Close()
}

var ErrNotFound = errors.New("vault entry not found")

func (v *TabVault) AppendToken(id string, token string) error {
	id = strings.TrimPrefix(id, "vault://")
	v.mu.Lock()
	defer v.mu.Unlock()

	existing, ok := v.secrets[id]
	if !ok {
		return ErrNotFound
	}

	v.secrets[id] = existing + " " + token

	return v.rewrite()
}

func (v *TabVault) rewrite() error {
	file, err := os.Create(v.filepath)
	if err != nil {
		return err
	}

	writer := csv.NewWriter(file)
	writer.Comma = '\t'
	_ = writer.Write([]string{"vault_id", "vault_secret"})
	for id, secret := range v.secrets {
		_ = writer.Write([]string{id, secret})
	}
	writer.Flush()

	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func (v *TabVault) Get(id string) string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.secrets[strings.TrimPrefix(id, "vault://")]
}

var ErrInvalidCredentials = errors.New("invalid credentials")

type BasicAuthPassword string

func (p BasicAuthPassword) Verify(_, password string) error {
	known := sha256.Sum256([]byte(p))
	digest := sha256.Sum256([]byte(password))
	if !bytes.Equal(known[:], digest[:]) {
		return ErrInvalidCredentials
	}
	return nil
}

func (v *TabVault) Verify(id string, password string) error {
	secret := v.Get(id)
	if secret == "" {
		return ErrInvalidCredentials
	}

	for token := range strings.SplitSeq(secret, " ") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if verifyOne(token, password) == nil {
			return nil
		}
	}
	return ErrInvalidCredentials
}

func verifyOne(secret, password string) error {
	if !strings.HasPrefix(secret, phcPrefix) {
		return BasicAuthPassword(secret).Verify("", password)
	}

	// $pbkdf2-sha256$iterations$salt_b64$hash_b64
	inner := secret[1:]
	parts := strings.SplitN(inner, "$", 4)
	if len(parts) != 4 {
		return ErrInvalidCredentials
	}

	iterations, err := strconv.Atoi(parts[1])
	if err != nil {
		return ErrInvalidCredentials
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return ErrInvalidCredentials
	}

	derived, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return ErrInvalidCredentials
	}

	dk, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return ErrInvalidCredentials
	}

	if subtle.ConstantTimeCompare(dk, derived) != 1 {
		return ErrInvalidCredentials
	}
	return nil
}
