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
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/rode/rode/common"
	"k8s.io/client-go/util/homedir"
	"path/filepath"
)

type entry struct {
	flags       []string
	expected    *Config
	expectError bool
}

var _ = DescribeTable("config",
	func(e entry) {
		conf, err := Build("rode", e.flags)
		if e.expectError {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).ToNot(HaveOccurred())
			Expect(conf).To(BeEquivalentTo(e.expected))
		}
	},
	Entry("base config", entry{
		flags: []string{"--policy-group=foo", "--tls-secret=foo/bar", "--rode-host=localhost:50051"},
		expected: &Config{
			Tls: &TlsConfig{
				Secret:    "foo/bar",
				Namespace: "foo",
				Name:      "bar",
			},
			Kubernetes: &KubernetesConfig{
				InCluster:  true,
				ConfigFile: filepath.Join(homedir.HomeDir(), ".kube", "config"),
			},
			PolicyGroup: "foo",
			ClientConfig: &common.ClientConfig{
				Rode: &common.RodeClientConfig{
					Host: "localhost:50051",
				},
				OIDCAuth:  &common.OIDCAuthConfig{},
				BasicAuth: &common.BasicAuthConfig{},
			},
			Port: 8001,
			Name: "k8s-enforcer",
		},
	}),
	Entry("missing policy group", entry{
		flags:       []string{"--tls-secret=foo/bar", "--rode-host=localhost:50051"},
		expectError: true,
	}),
	Entry("missing tls secret", entry{
		flags:       []string{"--policy-group=foo", "--rode-host=localhost:50051"},
		expectError: true,
	}),
	Entry("bad tls secret namespaced name", entry{
		flags:       []string{"--policy-group=foo", "--tls-secret=foo", "--rode-host=localhost:50051"},
		expectError: true,
	}),
	Entry("bad flag parsing", entry{
		flags:       []string{"--this isn't a flag"},
		expectError: true,
	}),
)
