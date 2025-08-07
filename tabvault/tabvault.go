package tabvault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"os"
	"strings"
	"sync"
)

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

func (v *TabVault) Get(id string) string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.secrets[strings.TrimPrefix(id, "vault://")]
}
