package tlsfront

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

const (
	diskProfileVersion = 1
	// diskProfileMaxBytes bounds the file read. A ServerHello record is at
	// most 16 KiB; its JSON and base64 encoding stay well below this.
	diskProfileMaxBytes = 64 << 10
	// diskProfileMaxAge rejects an old profile. The mask host can change its
	// TLS stack, so a profile older than this is not served.
	diskProfileMaxAge = 7 * 24 * time.Hour
	// diskProfileSaveInterval limits writes. Every fetch changes the random
	// bytes, so each refresh would otherwise write the file.
	diskProfileSaveInterval = time.Hour
	// maxCertRecordLen is the largest TLS 1.3 ciphertext record payload.
	maxCertRecordLen = 1<<14 + 256
)

// diskProfile is the file format of the cached TLS front profile.
type diskProfile struct {
	Version       int       `json:"version"`
	Host          string    `json:"host"`
	Port          int       `json:"port"`
	FetchedAt     time.Time `json:"fetched_at"`
	ServerHello   []byte    `json:"server_hello"`
	CertRecordLen int       `json:"cert_record_len"`
}

// diskProfilePath returns the cache file for one host and port. The name is
// a digest, so a host name cannot form a path.
func diskProfilePath(dir, host string, port int) string {
	sum := sha256.Sum256([]byte(net.JoinHostPort(host, strconv.Itoa(port))))
	return filepath.Join(dir, "serverhello-"+hex.EncodeToString(sum[:16])+".json")
}

// EnableDiskCache keeps the last good profile in dir. Call it before the
// first Refresh. An empty dir leaves the cache off.
func (f *ServerHelloFetcher) EnableDiskCache(dir string) {
	f.cacheDir = dir
}

// CheckDiskCacheDir creates dir when it is missing and checks that a cache
// file can be created in it, with the same calls that a save uses.
func CheckDiskCacheDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".serverhello-*.tmp")
	if err != nil {
		return err
	}
	closeErr := temp.Close()
	if err := os.Remove(temp.Name()); err != nil {
		return err
	}
	return closeErr
}

// LoadDiskCache publishes a cached profile when no fetch has succeeded yet.
// It checks the file like a fresh fetch: bounded size, the same host and
// port, an age limit, and a ServerHello that parses as a TLS 1.3 template.
// A file that fails a check is not used. The returned time is the fetch time
// of the loaded profile.
func (f *ServerHelloFetcher) LoadDiskCache() (time.Time, error) {
	if f.cacheDir == "" {
		return time.Time{}, nil
	}
	file, err := os.Open(diskProfilePath(f.cacheDir, f.host, f.port))
	if err != nil {
		return time.Time{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, diskProfileMaxBytes+1))
	if err != nil {
		return time.Time{}, err
	}
	profile, err := parseDiskProfile(data, f.host, f.port, time.Now())
	if err != nil {
		return time.Time{}, err
	}
	randomOffset, err := findServerHelloRandomOffset(profile.ServerHello)
	if err != nil {
		return time.Time{}, fmt.Errorf("cached ServerHello: %w", err)
	}
	template, err := faketls.ParseServerHelloTemplate(profile.ServerHello)
	if err != nil {
		return time.Time{}, fmt.Errorf("cached ServerHello: %w", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cachedFull != nil {
		return time.Time{}, errors.New("a fetched profile is already present")
	}
	f.cachedFull = profile.ServerHello
	f.randomOffset = randomOffset
	f.template = template
	f.certRecordLen = profile.CertRecordLen
	// The refresh period counts from the original fetch, so a stale profile
	// is fetched again at startup.
	f.lastFetch = profile.FetchedAt
	return profile.FetchedAt, nil
}

func parseDiskProfile(data []byte, host string, port int, now time.Time) (*diskProfile, error) {
	if len(data) > diskProfileMaxBytes {
		return nil, errors.New("cached profile is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var profile diskProfile
	if err := decoder.Decode(&profile); err != nil {
		return nil, fmt.Errorf("decode cached profile: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("cached profile has trailing data")
	}
	switch {
	case profile.Version != diskProfileVersion:
		return nil, fmt.Errorf("cached profile version %d is not supported", profile.Version)
	case profile.Host != host || profile.Port != port:
		return nil, errors.New("cached profile is for a different host")
	case profile.FetchedAt.After(now.Add(time.Minute)):
		return nil, errors.New("cached profile is from the future")
	case now.Sub(profile.FetchedAt) > diskProfileMaxAge:
		return nil, errors.New("cached profile is too old")
	case profile.CertRecordLen < 0 || profile.CertRecordLen > maxCertRecordLen:
		return nil, errors.New("cached certificate record length is out of range")
	}
	return &profile, nil
}

// saveDiskCache writes the profile with a temporary file and a rename, so a
// reader never sees a partial file.
func (f *ServerHelloFetcher) saveDiskCache(serverHello []byte, certRecordLen int, fetchedAt time.Time) error {
	data, err := json.Marshal(diskProfile{
		Version:       diskProfileVersion,
		Host:          f.host,
		Port:          f.port,
		FetchedAt:     fetchedAt.UTC(),
		ServerHello:   serverHello,
		CertRecordLen: certRecordLen,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(f.cacheDir, 0o700); err != nil {
		return err
	}
	path := diskProfilePath(f.cacheDir, f.host, f.port)
	temp, err := os.CreateTemp(f.cacheDir, ".serverhello-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

// persist saves a new profile at most once per diskProfileSaveInterval.
// Only a TLS 1.3 template is saved, because only a template is served.
func (f *ServerHelloFetcher) persist(serverHello []byte, certRecordLen int, fetchedAt time.Time) {
	if f.cacheDir == "" || !f.lastSave.IsZero() && fetchedAt.Sub(f.lastSave) < diskProfileSaveInterval {
		return
	}
	if err := f.saveDiskCache(serverHello, certRecordLen, fetchedAt); err != nil {
		if f.saveError != nil {
			f.saveError(err)
		}
		return
	}
	f.lastSave = fetchedAt
}

// OnDiskCacheError sets a callback for failed cache writes. A failed write
// does not fail the refresh.
func (f *ServerHelloFetcher) OnDiskCacheError(report func(error)) {
	f.saveError = report
}
