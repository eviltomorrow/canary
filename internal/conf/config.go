package conf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/eviltomorrow/canary/pkg/system"
)

type Config struct {
	System System `json:"system" toml:"system"`
	Log    Log    `json:"log" toml:"log"`
	Server Server `json:"server" toml:"server"`
}

type System struct {
	FileDir string `json:"file-dir" toml:"file-dir"`
}

type Log struct {
	DisableTimestamp bool   `json:"disable-timestamp" toml:"disable-timestamp"`
	Level            string `json:"level" toml:"level"`
	Format           string `json:"format" toml:"format"`
	MaxSize          int    `json:"maxsize" toml:"maxsize"`
}

type Server struct {
	Host string `json:"host" toml:"host"`
	Port int    `json:"port" toml:"port"`
}

func (c *Config) Load(path string, override func(cfg *Config)) error {
	findPath := func() (string, error) {
		var possibleConf = []string{
			path,
			filepath.Join(system.Pwd, "etc/config.toml"),
			"../etc/config.toml",
		}
		for _, path := range possibleConf {
			if path == "" {
				continue
			}
			if _, err := os.Stat(path); err == nil {
				fp, err := filepath.Abs(path)
				if err == nil {
					return fp, nil
				}
				return path, nil
			}
		}
		return "", fmt.Errorf("not found conf file, possible conf %v", possibleConf)
	}
	conf, err := findPath()
	if err != nil {
		return err
	}

	if _, err := toml.DecodeFile(conf, c); err != nil {
		return err
	}
	return nil
}

func (cg *Config) String() string {
	buf, _ := json.Marshal(cg)
	return string(buf)
}

var Global = &Config{
	Log: Log{
		DisableTimestamp: false,
		Level:            "info",
		Format:           "text",
		MaxSize:          20,
	},
}
