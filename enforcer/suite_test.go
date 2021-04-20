package enforcer

import (
	"github.com/brianvoe/gofakeit/v6"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"

	"testing"
)

var logger = zap.NewNop()
var fake = gofakeit.New(0)

func TestEnforcer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Enforcer Suite")
}
