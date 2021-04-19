package config

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("config",
	func(flags []string, expectError bool, expected *Config) {
		conf, err := Build("rode", flags)
		if expectError {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).ToNot(HaveOccurred())
			Expect(conf).To(BeEquivalentTo(expected))
		}
	},
	Entry("base config", []string{"--policy-id=foo", "--tls-secret=foo/bar", "--rode-host=localhost:50051"}, false, &Config{
		Tls: &TlsConfig{
			Secret:    "foo/bar",
			Namespace: "foo",
			Name:      "bar",
		},
		PolicyId: "foo",
		RodeHost: "localhost:50051",
		Port:     8001,
	}),
)
