// Package config loads the non-secret nas-secrets settings that Nix renders
// into the store. Raw JSON is decoded strictly and converted into validated
// types once; the rest of the program never sees unvalidated strings.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"

	"github.com/TheDirepack/Nix-nas/go/internal/keepass"
	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
)

type rawFeatures struct {
	Observability bool `json:"observability"`
	Grafana       bool `json:"grafana"`
	Ntfy          bool `json:"ntfy"`
	NutWeb        bool `json:"nutWeb"`
	ZFSEncryption bool `json:"zfsEncryption"`
	Vaultwarden   bool `json:"vaultwarden"`
}

type raw struct {
	SchemaVersion                    int         `json:"schemaVersion"`
	Database                         string      `json:"database"`
	KeyFile                          string      `json:"keyFile"`
	Group                            string      `json:"group"`
	SecretRoot                       string      `json:"secretRoot"`
	RuntimeRoot                      string      `json:"runtimeRoot"`
	LockFile                         string      `json:"lockFile"`
	SetupState                       string      `json:"setupState"`
	ProtectedTarget                  string      `json:"protectedTarget"`
	V2SystemdState                   string      `json:"v2SystemdState"`
	BootstrapAuthentikDir            string      `json:"bootstrapAuthentikDir"`
	AuthentikRuntimeEnvironmentFile  string      `json:"authentikRuntimeEnvironmentFile"`
	AuthentikUnlockedEnvironmentFile string      `json:"authentikUnlockedEnvironmentFile"`
	AuthentikRuntimeOutpostTokenFile string      `json:"authentikRuntimeOutpostTokenFile"`
	AuthentikAPITokenFile            string      `json:"authentikApiTokenFile"`
	AuthentikRuntimeAPITokenFile     string      `json:"authentikRuntimeApiTokenFile"`
	AuthentikReadyURL                string      `json:"authentikReadyUrl"`
	BootstrapEmail                   string      `json:"bootstrapEmail"`
	OperationRunner                  string      `json:"operationRunner"`
	Features                         rawFeatures `json:"features"`
}

// Features are the optional secret consumers.
type Features struct {
	Observability, Grafana, Ntfy, NutWeb, ZFSEncryption, Vaultwarden bool
}

// Email is a bootstrap address that renders safely inside single quotes.
type Email struct{ s string }

// emailPattern is the Nix option's shape minus quotes and backslashes, so
// the value renders safely inside single quotes.
var emailPattern = regexp.MustCompile(`^[^\s@'"\\\x00-\x1f\x7f]+@[^\s@'"\\\x00-\x1f\x7f]+$`)

func (e Email) String() string { return e.s }

// Settings is the validated configuration.
type Settings struct {
	Database                         syspath.Abs
	KeyFile                          *syspath.Abs
	Group                            keepass.Group
	SecretRoot                       syspath.Abs
	RuntimeRoot                      syspath.Abs
	LockFile                         syspath.Abs
	SetupState                       syspath.Abs
	ProtectedTarget                  syspath.Target
	V2SystemdState                   syspath.Abs
	BootstrapAuthentikDir            syspath.Abs
	AuthentikRuntimeEnvironmentFile  syspath.Abs
	AuthentikUnlockedEnvironmentFile syspath.Abs
	AuthentikRuntimeOutpostTokenFile syspath.Abs
	AuthentikAPITokenFile            syspath.Abs
	AuthentikRuntimeAPITokenFile     syspath.Abs
	AuthentikReadyURL                *url.URL
	BootstrapEmail                   Email
	OperationRunner                  syspath.Abs
	Features                         Features
}

// Load reads and validates a settings file.
func Load(path string) (*Settings, error) {
	data, err := os.ReadFile(path) // #nosec -- path is the Nix-pinned configuration
	if err != nil {
		return nil, fmt.Errorf("nas-secrets configuration: %w", err)
	}
	return Parse(data)
}

// Parse validates a settings document.
func Parse(data []byte) (*Settings, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r raw
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("nas-secrets configuration: %w", err)
	}
	if r.SchemaVersion != 1 {
		return nil, fmt.Errorf("nas-secrets configuration: unsupported schemaVersion %d", r.SchemaVersion)
	}
	var errs []error
	abs := func(label, v string) syspath.Abs {
		a, err := syspath.NewAbs(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", label, err))
		}
		return a
	}
	s := &Settings{
		Database:                         abs("database", r.Database),
		SecretRoot:                       abs("secretRoot", r.SecretRoot),
		RuntimeRoot:                      abs("runtimeRoot", r.RuntimeRoot),
		LockFile:                         abs("lockFile", r.LockFile),
		SetupState:                       abs("setupState", r.SetupState),
		V2SystemdState:                   abs("v2SystemdState", r.V2SystemdState),
		BootstrapAuthentikDir:            abs("bootstrapAuthentikDir", r.BootstrapAuthentikDir),
		AuthentikRuntimeEnvironmentFile:  abs("authentikRuntimeEnvironmentFile", r.AuthentikRuntimeEnvironmentFile),
		AuthentikUnlockedEnvironmentFile: abs("authentikUnlockedEnvironmentFile", r.AuthentikUnlockedEnvironmentFile),
		AuthentikRuntimeOutpostTokenFile: abs("authentikRuntimeOutpostTokenFile", r.AuthentikRuntimeOutpostTokenFile),
		AuthentikAPITokenFile:            abs("authentikApiTokenFile", r.AuthentikAPITokenFile),
		AuthentikRuntimeAPITokenFile:     abs("authentikRuntimeApiTokenFile", r.AuthentikRuntimeAPITokenFile),
		OperationRunner:                  abs("operationRunner", r.OperationRunner),
		Features:                         Features(r.Features),
	}
	if r.KeyFile != "" {
		k := abs("keyFile", r.KeyFile)
		s.KeyFile = &k
	}
	var err error
	if s.Group, err = keepass.NewGroup(r.Group); err != nil {
		errs = append(errs, err)
	}
	if s.ProtectedTarget, err = syspath.NewTarget(r.ProtectedTarget); err != nil {
		errs = append(errs, err)
	}
	u, err := url.Parse(r.AuthentikReadyURL)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil {
		errs = append(errs, fmt.Errorf("authentikReadyUrl must be a plain http URL"))
	}
	s.AuthentikReadyURL = u
	if !emailPattern.MatchString(r.BootstrapEmail) {
		errs = append(errs, fmt.Errorf("bootstrapEmail is not a plain address"))
	}
	s.BootstrapEmail = Email{s: r.BootstrapEmail}
	if len(errs) > 0 {
		return nil, fmt.Errorf("nas-secrets configuration: %v", errs)
	}
	return s, nil
}
