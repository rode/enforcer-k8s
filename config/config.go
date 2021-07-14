// Copyright 2021 The Rode Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"errors"
	"flag"
	"github.com/rode/rode/common"
	"path/filepath"
	"strings"

	"k8s.io/client-go/util/homedir"
)

type Config struct {
	Debug                      bool
	RegistryInsecureSkipVerify bool
	Kubernetes                 *KubernetesConfig
	Namespace                  string
	PolicyGroup                string
	Port                       int
	ClientConfig               *common.ClientConfig
	Tls                        *TlsConfig
	Name                       string
}

type TlsConfig struct {
	Secret    string
	Name      string
	Namespace string
}

type KubernetesConfig struct {
	InCluster  bool
	ConfigFile string
}

func Build(name string, args []string) (*Config, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)

	conf := &Config{
		Tls:          &TlsConfig{},
		Kubernetes:   &KubernetesConfig{},
		ClientConfig: common.SetupRodeClientFlags(flags),
	}

	flags.StringVar(&conf.PolicyGroup, "policy-group", "", "the name of the rode policy group to evaluate against when attempting to admit a pod")
	flags.StringVar(&conf.Tls.Secret, "tls-secret", "", "the namespaced name of the TLS secret containing the certificate / private key for the webhook TLS configuration. should be in the format ${namespace}/${name}")
	flags.BoolVar(&conf.RegistryInsecureSkipVerify, "registry-insecure-skip-verify", false, "when set, TLS connections to container registries will be insecure")
	flags.BoolVar(&conf.Debug, "debug", false, "when set, debug mode will be enabled")
	flags.IntVar(&conf.Port, "port", 8001, "the port to bind")
	flags.StringVar(&conf.Name, "name", "k8s-enforcer", "the name of this enforcer, used when reporting resource evaluation results to rode")

	flags.BoolVar(&conf.Kubernetes.InCluster, "k8s-in-cluster", true, "when set, the enforcer will use the in-cluster k8s config")
	flags.StringVar(&conf.Kubernetes.ConfigFile, "k8s-config-file", filepath.Join(homedir.HomeDir(), ".kube", "config"), "path to k8s config file when running outside the cluster")

	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	if conf.PolicyGroup == "" {
		return nil, errors.New("--policy-group is required")
	}

	if conf.Tls.Secret == "" {
		return nil, errors.New("--tls-secret is required")
	}

	if conf.ClientConfig.Rode.Host == "" {
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
