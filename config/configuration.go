package config

import (
	"os"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/file"
	"github.com/rotisserie/eris"
)

const (
	delimiter       = "."
	configFilePerm  = os.FileMode(0o600)
	defaultFileName = "famed-annotated.yml"
)

// DefaultConfig returns a fully initialized(? maybe not the best word) configuration.
func NewDefault() error {
	k := koanf.New(delimiter)

	// Load defaults values
	err := k.Load(confmap.Provider(map[string]interface{}{
		"project.name":        "famed-annotated",
		"project.description": "A famed-annotated project.",
		"imports":             []string{"./"},
		"paths":               []string{"./"},
	}, delimiter), nil)
	if err != nil {
		return eris.Wrap(err, "failed to load configuration from default values")
	}

	b, err := k.Marshal(yaml.Parser())
	if err != nil {
		return eris.Wrap(err, "failed to marshal configuration")
	}

	if err := os.WriteFile(defaultFileName, b, configFilePerm); err != nil {
		return eris.Wrap(err, "failed to write file")
	}

	return nil
}

// LoadFile retrieves values from filePath configuration file.
func LoadFile() (*Config, error) {
	k := koanf.New(delimiter)

	configFile, err := os.Stat(defaultFileName)
	if err != nil {
		return nil, eris.Wrap(err, defaultFileName+" does not exist")
	}

	if err := k.Load(file.Provider(configFile.Name()), yaml.Parser()); err != nil {
		return nil, eris.Wrap(err, "failed to load yaml file")
	}

	config := &Config{}

	if err = k.Unmarshal("", &config); err != nil {
		return nil, eris.Wrap(err, "failed to unmarshal config")
	}

	return config, nil
}
