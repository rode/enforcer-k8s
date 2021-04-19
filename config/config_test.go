package config

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
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
		flags: []string{"--policy-id=foo", "--tls-secret=foo/bar", "--rode-host=localhost:50051"},
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
			PolicyId: "foo",
			RodeHost: "localhost:50051",
			Port:     8001,
		},
	}),
	Entry("missing policy ID", entry{
		flags:       []string{"--tls-secret=foo/bar", "--rode-host=localhost:50051"},
		expectError: true,
	}),
	Entry("missing tls secret", entry{
		flags:       []string{"--policy-id=foo", "--rode-host=localhost:50051"},
		expectError: true,
	}),
	Entry("missing rode host", entry{
		flags:       []string{"--policy-id=foo", "--tls-secret=foo/bar"},
		expectError: true,
	}),
	Entry("bad tls secret namespaced name", entry{
		flags:       []string{"--policy-id=foo", "--tls-secret=foo", "--rode-host=localhost:50051"},
		expectError: true,
	}),
	Entry("bad flag parsing", entry{
		flags:       []string{"--this isn't a flag"},
		expectError: true,
	}),
)
