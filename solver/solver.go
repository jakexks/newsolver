/*
Copyright The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// solver is a backend for HTTP-01 challenges
package solver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/go-logr/logr"
	"github.com/soheilhy/cmux"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	acmev1 "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	"github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
)

// HTTP01Solver is a controller for cert-manager challenges
type HTTP01Solver struct {
	ListenPort         int
	GetCertificateFunc func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

func (h *HTTP01Solver) Start(ctx context.Context, log logr.Logger) error {
	scheme := runtime.NewScheme()
	if err := acmev1.AddToScheme(scheme); err != nil {
		log.Error(err, "couldn't add to scheme")
		return err
	}

	mgr, err := manager.New(config.GetConfigOrDie(), manager.Options{
		Scheme: scheme,
		Logger: log,
	})
	if err != nil {
		log.Error(err, "couldn't create manager")
		return err
	}

	r := &reconciler{
		scheme:     mgr.GetScheme(),
		cmClient:   versioned.NewForConfigOrDie(mgr.GetConfig()),
		log:        log,
		challenges: make(map[types.NamespacedName]*acmev1.Challenge),
		tokens:     make(map[string]string),
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&acmev1.Challenge{}).
		Complete(r); err != nil {
		log.Error(err, "couldn't create controller")
		return err
	}

	log.Info("Starting controller")
	go func() {
		if err := mgr.Start(ctx); err != nil {
			log.Error(err, "manager couldn't start")
		}
	}()

	log.Info("Starting listener", "port", h.ListenPort)
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", h.ListenPort))
	if err != nil {
		return err
	}
	m := cmux.New(l)
	// Special case HTTP, assume everything else is HTTPS
	httpL := m.Match(cmux.HTTP1Fast())
	httpsL := m.Match(cmux.Any())

	httpS := &http.Server{
		Handler: http.HandlerFunc(r.handler),
	}
	httpsS := &http.Server{
		Handler: http.HandlerFunc(r.handler),
		TLSConfig: &tls.Config{
			GetCertificate: h.GetCertificateFunc,
		},
	}

	go func() {
		log.Info("Starting http server")
		if err := httpS.Serve(httpL); err != nil {
			log.Error(err, "solver http server closing")
		}
	}()
	go func() {
		log.Info("Starting https server")
		if err := httpsS.ServeTLS(httpsL, "", ""); err != nil {
			log.Error(err, "solver tls server closing")
		}
	}()
	go func() {
		if err := m.Serve(); err != nil {
			log.Error(err, "listener closing")
		}
	}()

	<-ctx.Done()
	httpS.Shutdown(ctx)
	httpsS.Shutdown(ctx)

	return ctx.Err()
}
