package solver

import (
	"context"
	"net/http"
	"path"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/go-logr/logr"
	acmev1 "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
)

type reconciler struct {
	cmClient *cmclient.Clientset
	scheme   *runtime.Scheme

	challenges map[types.NamespacedName]*acmev1.Challenge
	// map token:key
	tokens map[string]string

	log logr.Logger
	sync.RWMutex
}

func (r *reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.log
	log.Info("saw challenge", "challenge", req.NamespacedName)
	challenge, err := r.cmClient.AcmeV1().Challenges(req.Namespace).Get(ctx, req.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		r.Lock()
		oldChallenge, found := r.challenges[req.NamespacedName]
		if found {
			delete(r.tokens, oldChallenge.Spec.Token)
		}
		delete(r.challenges, req.NamespacedName)
		r.Unlock()
	} else if err != nil {
		return ctrl.Result{}, err
	}
	r.Lock()
	r.challenges[req.NamespacedName] = challenge
	r.tokens[challenge.Spec.Token] = challenge.Spec.Key
	println("wrote", challenge.Spec.Token, challenge.Spec.Key)
	r.Unlock()
	return ctrl.Result{}, nil
}

func (r *reconciler) handler(w http.ResponseWriter, req *http.Request) {
	//host := strings.Split(req.Host, ":")[0]
	basePath := path.Dir(req.URL.EscapedPath())
	token := path.Base(req.URL.EscapedPath())

	if req.URL.EscapedPath() == "/" || req.URL.EscapedPath() == "/healthz" {
		r.log.Info("responding to healthz")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.WriteHeader(http.StatusOK)
		return
	}
	r.log.Info("validating request")
	// verify the base path is correct
	if basePath != HTTPChallengePath {
		r.log.Info("invalid base_path", "expected_base_path", HTTPChallengePath)
		http.NotFound(w, req)
		return
	}
	r.RLock()
	defer r.RUnlock()
	// verify token
	key, found := r.tokens[token]
	if !found {
		r.log.Info("invalid_token", "token", token)
		http.NotFound(w, req)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(key))
}
