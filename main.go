package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/go-logr/logr"
	"github.com/jakexks/newsolver/solver"
	"github.com/jetstack/cert-manager/pkg/util"
	utilcmd "github.com/jetstack/cert-manager/pkg/util/cmd"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func main() {
	stopCh := utilcmd.SetupSignalHandler()
	ctx := util.ContextWithStopCh(context.Background(), stopCh)
	log := DebugLogger{}

	s := &solver.HTTP01Solver{
		ListenPort: 9090,
		GetCertificateFunc: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			k, _ := pki.GenerateECPrivateKey(pki.ECCurve256)
			tmpl := x509.Certificate{
				SerialNumber: big.NewInt(42),
				Subject: pkix.Name{
					Organization: []string{"Acme Co"},
					CommonName:   "Self Signed",
				},
				NotBefore:             time.Now().Add(-time.Second),
				NotAfter:              time.Now().Add(time.Hour),
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
				IsCA:                  true,
			}
			der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &k.PublicKey, k)
			if err != nil {
				return nil, err
			}
			return &tls.Certificate{
				Certificate: [][]byte{der},
				PrivateKey:  k,
			}, nil
		},
	}

	go func() {
		if err := s.Start(ctx, log); err != nil {
			println(err)
		}
	}()

	<-stopCh
	log.Info("server shutting down...")
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(3*time.Second))
	<-ctx.Done()
	cancel()
	log.Info("bye!")
}

type DebugLogger struct{}

func (d DebugLogger) Enabled() bool {
	return true
}

func (d DebugLogger) Info(msg string, keysAndValues ...interface{}) {
	fmt.Print("INFO ")
	fmt.Printf("%s ", msg)
	fmt.Println(keysAndValues...)
}

func (d DebugLogger) Error(err error, msg string, keysAndValues ...interface{}) {
	fmt.Print("ERROR ")
	fmt.Printf("%v ", err)
	fmt.Printf("%s ", msg)
	fmt.Println(keysAndValues...)
}

func (d DebugLogger) V(int) logr.Logger {
	return d
}

func (d DebugLogger) WithValues(keysAndValues ...interface{}) logr.Logger {
	return d
}

func (d DebugLogger) WithName(name string) logr.Logger {
	return d
}
