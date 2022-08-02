package config

// Config is the complete representation of the configuration, it is authoritative on configuration names, hierarchy, structure and type.
type Config struct {
	Imports []string `koanf:"imports"`
	Project struct {
		Name        string `koanf:"name"`
		Description string `koanf:"description"`
	} `koanf:"project"`
	RepositoryURL string `koanf:"repository_url"`
}
