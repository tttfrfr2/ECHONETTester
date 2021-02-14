package util

import (
	"fmt"
	"github.com/BurntSushi/toml"
)

type Config struct {
	Title       string
	EchonetLite EchonetLiteConf
}
type EchonetLiteConf struct {
	IP []string
}

func ReadConfig(filePath string) *Config {
	var config Config
	_, err := toml.DecodeFile(filePath, &config)
	if err != nil {
		fmt.Printf("Read TOML Error: %s\n", err)
		return nil
	}
	return &config
}

func DistributeConf(config Config) EchonetLiteConf {
	return config.EchonetLite
}
