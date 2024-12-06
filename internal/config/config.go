package config

import (
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

type Server struct {
	Host    string        `yaml:"host"`
	Port    int           `yaml:"port"`
	Timeout time.Duration `yaml:"timeout" env-default:"10s"`
}

type Database struct {
	Host     string `yaml:"host"`
	Port     uint16 `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Name     string `yaml:"name"`
}

type HTTP struct {
	Timeout     time.Duration `yaml:"timeout" env-default:"5s"`
	IdleTimeout time.Duration `yaml:"idle_timeout" env-default:"60s"`
}

type JWT struct {
	SecretKey      string        `yaml:"secret_key"`
	AccessExpires  time.Duration `yaml:"access_token_expires" env-default:"300s"`
	RefreshExpires time.Duration `yaml:"refresh_token_expires" env-default:"3600s"`
}

type Email struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	From     string `yaml:"from"`
	Password string `yaml:"password"`
}

type Config struct {
	Env      string   `yaml:"env"`
	Server   Server   `yaml:"server"`
	Database Database `yaml:"database"`
	Email    Email    `yaml:"email"`
	HTTP     HTTP     `yaml:"http"`
	JWT      JWT      `yaml:"jwt"`
}

func MustLoad(configPath string) *Config {
	if configPath == "" {
		log.Fatalf("CONFIG_PATH is not set")
	}

	if _, err := os.Stat(configPath); err != nil {
		log.Fatalf("Can not to find config file: %s", err)
	}

	file, err := os.Open(configPath)

	if err != nil {
		log.Fatalf("Can not to open config file: %s", err)
	}
	defer file.Close()

	var cfg Config

	decoder := yaml.NewDecoder(file)

	if err := decoder.Decode(&cfg); err != nil {
		log.Fatalf("Can not to read config file: %s", err)
	}

	return &cfg
}
