package config

import (
	"errors"
	"flag"
	"strings"
)

type Config struct {
	PolicyId  string
	Tls       *TlsConfig
	Port      int
	RodeHost  string
	Namespace string
}

type TlsConfig struct {
	Secret    string
	Name      string
	Namespace string
}

func Build(name string, args []string) (*Config, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)

	conf := &Config{
		Tls: &TlsConfig{},
	}

	flags.StringVar(&conf.PolicyId, "policy-id", "", "the ID of the rode policy to evaluate when attempting to admit a pod")
	flags.StringVar(&conf.Tls.Secret, "tls-secret", "", "the namespaced name of the TLS secret containing the certificate / private key for the webhook TLS configuration. should be in the format ${namespace}/${name}")
	flags.StringVar(&conf.RodeHost, "rode-host", "", "rode host")
	flags.IntVar(&conf.Port, "port", 8001, "the port to bind")

	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	if conf.PolicyId == "" {
		return nil, errors.New("--policy-id is required")
	}

	if conf.Tls.Secret == "" {
		return nil, errors.New("--tls-secret is required")
	}

	if conf.RodeHost == "" {
		return nil, errors.New("--rode-host is required")
	}

	if parts := strings.Split(conf.Tls.Secret, "/"); len(parts) != 2 {
		return nil, errors.New("expected tls secret to be in the format ${namespace}/${name}")
	} else {
		conf.Tls.Namespace = parts[0]
		conf.Tls.Name = parts[1]
	}

	return conf, nil
}