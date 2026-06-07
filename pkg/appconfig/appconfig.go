// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package appconfig

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Config is the top-level YAML configuration for multi-org GitHub App routing.
type Config struct {
	Orgs []OrgConfig `mapstructure:"orgs"`
}

// OrgConfig binds a GitHub organization to one or more GitHub Apps.
type OrgConfig struct {
	Name string      `mapstructure:"name"`
	Apps []AppConfig `mapstructure:"apps"`
}

// AppConfig describes a single GitHub App and its credential source.
// Exactly one of KMSKey, PrivateKeyFile, or PrivateKey must be set.
type AppConfig struct {
	AppID          int64  `mapstructure:"app_id"`
	KMSKey         string `mapstructure:"kms_key,omitempty"`
	PrivateKeyFile string `mapstructure:"private_key_file,omitempty"`
	PrivateKey     string `mapstructure:"private_key,omitempty"`
}

// Load reads YAML config from one or more files and returns the parsed
// Config. When multiple files are supplied, later files override earlier
// ones (koanf merge semantics).
func Load(appliers ...OptionsApplier) (*Config, error) {
	options := NewOptions(appliers...)
	if len(options.ConfigFilePath) == 0 {
		return nil, errors.New("config files are missing")
	}

	k := koanf.New(options.ConfigKeyDelimiter)

	parser := envExpandingParser{inner: yaml.Parser()}

	for _, filename := range options.ConfigFilePath {
		if filename == "" {
			continue
		}
		if err := k.Load(file.Provider(filename), parser); err != nil {
			return nil, fmt.Errorf("error reading config file %q: %w", filename, err)
		}
	}

	var cfg *Config
	if err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{
		Tag: options.TagName,
		DecoderConfig: &mapstructure.DecoderConfig{
			ErrorUnused: true,
		},
	}); err != nil {
		return nil, fmt.Errorf("error unmarshalling config: %w", err)
	}
	if cfg == nil {
		return nil, errors.New("config is empty")
	}
	return cfg, nil
}

// envExpandingParser wraps a koanf Parser and substitutes ${VAR} env
// references in every string leaf of the parsed map. Done post-parse so
// multi-line env values (e.g. PEMs) aren't subject to YAML line-folding
// or block-scalar indentation rules.
type envExpandingParser struct {
	inner koanf.Parser
}

func (p envExpandingParser) Unmarshal(b []byte) (map[string]any, error) {
	m, err := p.inner.Unmarshal(b)
	if err != nil {
		return nil, err
	}
	expandEnvInPlace(m)
	return m, nil
}

func (p envExpandingParser) Marshal(m map[string]any) ([]byte, error) {
	return p.inner.Marshal(m)
}

func expandEnvInPlace(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok {
				x[k] = os.ExpandEnv(s)
			} else {
				expandEnvInPlace(val)
			}
		}
	case []any:
		for i, val := range x {
			if s, ok := val.(string); ok {
				x[i] = os.ExpandEnv(s)
			} else {
				expandEnvInPlace(val)
			}
		}
	}
}

// Validate checks the config for structural errors:
//   - at least one org
//   - no duplicate org names (case-insensitive)
//   - no duplicate app IDs (globally)
//   - at least one app per org
//   - exactly one credential source per app
//
// Org names are normalized to lowercase since GitHub organization names
// are case-insensitive.
func (c *Config) Validate() error {
	if len(c.Orgs) == 0 {
		return fmt.Errorf("config must have at least one org")
	}

	orgNames := make(map[string]bool)
	appIDs := make(map[int64]bool)

	for i := range c.Orgs {
		c.Orgs[i].Name = strings.ToLower(c.Orgs[i].Name)
		org := c.Orgs[i]
		if org.Name == "" {
			return fmt.Errorf("org name must not be empty")
		}
		if orgNames[org.Name] {
			return fmt.Errorf("duplicate org name: %q", org.Name)
		}
		orgNames[org.Name] = true

		if len(org.Apps) == 0 {
			return fmt.Errorf("org %q must have at least one app", org.Name)
		}

		for _, app := range org.Apps {
			if app.AppID == 0 {
				return fmt.Errorf("org %q: app_id must not be zero", org.Name)
			}
			if appIDs[app.AppID] {
				return fmt.Errorf("duplicate app_id: %d", app.AppID)
			}
			appIDs[app.AppID] = true

			sources := 0
			if app.KMSKey != "" {
				sources++
			}
			if app.PrivateKeyFile != "" {
				sources++
			}
			if app.PrivateKey != "" {
				sources++
			}
			if sources != 1 {
				return fmt.Errorf("org %q, app %d: exactly one of kms_key, private_key_file, or private_key must be set", org.Name, app.AppID)
			}
		}
	}

	return nil
}
