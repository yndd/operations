/*
Copyright 2022.

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

package controllers

import (
	"context"
	"fmt"
	"net"
	"time"

	certv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/pkg/errors"
	"github.com/yndd/ndd-runtime/pkg/logging"
	"github.com/yndd/ndd-runtime/pkg/resource"
	targetv1 "github.com/yndd/ndd-target-runtime/apis/dvr/v1"
	yndddevv1alpha1 "github.com/yndd/operations/api/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	gnoiapi "github.com/karimra/gnoic/api"
	gnoicert "github.com/karimra/gnoic/api/cert"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// CertificateProfileReconciler reconciles a CertificateProfile object
type CertificateProfileReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Logger logging.Logger
}

//+kubebuilder:rbac:groups=yndd.dev,resources=certificateprofiles,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=yndd.dev,resources=certificateprofiles/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=yndd.dev,resources=certificateprofiles/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the CertificateProfile object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.11.0/pkg/reconcile
func (r *CertificateProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Logger.WithValues("request", req)
	logger.Info("reconciling")

	certProf := new(yndddevv1alpha1.CertificateProfile)

	err := r.Client.Get(ctx, req.NamespacedName, certProf)
	if err != nil {
		if kerrors.IsNotFound(err) {
			logger.Debug("certificate-profile not found")
			return ctrl.Result{}, nil
		}
		logger.Debug("could not get certificate profile", "error", err)
		return reconcile.Result{},
			errors.Wrap(err, "could not get certificate profile")
	}
	logger.Info("reconcile certificateProfile", "certificateProfile", certProf.GetObjectKind())
	//
	matchingTargets, err := r.selectTargets(ctx, certProf)
	if err != nil {
		return reconcile.Result{RequeueAfter: 10 * time.Second},
			errors.Wrap(resource.IgnoreNotFound(err), "failed to find targets")
	}

	numMatchingTargets := len(matchingTargets)
	logger.Debug("found targets", "number", numMatchingTargets)
	errs := make([]error, 0, numMatchingTargets)
	if numMatchingTargets == 0 {
		logger.Info("no matching targets")
		return ctrl.Result{}, nil
	}
	for _, tg := range matchingTargets {
		err = r.handleTarget(ctx, tg, certProf)
		if err != nil {
			logger.Info("target handling failed",
				"target", tg.GetName(),
				"error", err)
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return ctrl.Result{
			Requeue:      true,
			RequeueAfter: 10 * time.Second,
		}, fmt.Errorf("%v", errs)
	}
	logger.Info("reconcile done", "result", "no errors")
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	targetManager := &targetHandler{
		client: mgr.GetClient(),
		log:    r.Logger,
	}
	certificateManager := &certificateHandler{
		client: mgr.GetClient(),
		log:    r.Logger,
	}
	secretManager := &secretHandler{
		client: mgr.GetClient(),
		log:    r.Logger,
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&yndddevv1alpha1.CertificateProfile{}).
		Owns(&yndddevv1alpha1.CertificateProfile{}).
		Watches(
			&source.Kind{Type: &targetv1.Target{}},
			targetManager,
		).
		Watches(
			&source.Kind{Type: &certv1.Certificate{}},
			certificateManager,
		).
		Watches(
			&source.Kind{Type: &corev1.Secret{}},
			secretManager,
		).
		Complete(r)
}

func buildCertObj(cProf yndddevv1alpha1.CertificateProfile, tg targetv1.Target) *certv1.Certificate {
	certName := fmt.Sprintf("%s-%s", cProf.GetName(), tg.GetName())
	secretName := secretName(cProf.GetName(), tg.GetName(), cProf.Spec.Properties.SecretName)
	spec := cProf.Spec.Properties
	spec.SecretName = secretName
	tgSpec, err := tg.GetSpec()
	if err != nil {

	} else {
		if len(spec.IPAddresses) == 0 {
			addr, _, err := net.SplitHostPort(*tgSpec.Config.Address)
			if err == nil {
				spec.IPAddresses = []string{addr}
			}
		}
	}
	cert := &certv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certName,
			Namespace: tg.Namespace,
			Labels: map[string]string{
				"operations":          "true",
				"certificate-profile": cProf.Name,
				"target":              tg.Name,
			},
		},
		Spec: spec,
	}
	return cert
}

func (r *CertificateProfileReconciler) selectTargets(ctx context.Context, cp *yndddevv1alpha1.CertificateProfile) ([]targetv1.Target, error) {
	logger := r.Logger.WithValues(
		"certificate-profile", fmt.Sprintf("%s/%s", cp.GetNamespace(), cp.GetName()),
	)
	// if there is a target reference under CertificateProfile, use that target
	if cp.Spec.TargetSelector != nil {
		logger.Debug("selecting target(s) based on targetSelector")
		targetNamespace := cp.Spec.TargetSelector.Namespace
		if targetNamespace == "" {
			targetNamespace = cp.GetNamespace()
		}
		validatedLabels, err := labels.ValidatedSelectorFromSet(cp.Spec.TargetSelector.Labels)
		if err != nil {
			return nil, err
		}
		tgs := &targetv1.TargetList{}
		err = r.Client.List(ctx, tgs, &client.ListOptions{
			Namespace:     targetNamespace,
			LabelSelector: validatedLabels,
		})
		if err != nil {
			return nil, err
		}
		return tgs.Items, nil
	}

	// otherwise select using target labels
	labelsSet := map[string]string{
		"yndd.io/certificate-profile": fmt.Sprintf("%s", cp.GetName()),
	}
	logger.Debug("selecting target(s) based on labels", "labelsSet", labelsSet)
	validatedLabels, err := labels.ValidatedSelectorFromSet(labelsSet)
	if err != nil {
		return nil, err
	}
	tgs := &targetv1.TargetList{}
	err = r.Client.List(ctx, tgs, &client.ListOptions{
		LabelSelector: validatedLabels,
	})
	if err != nil {
		return nil, err
	}
	return tgs.Items, nil
}

func (r *CertificateProfileReconciler) createGNOITarget(ctx context.Context, namespace string, tg targetv1.Target) (*gnoiapi.Target, error) {
	tgSpec, err := tg.GetSpec()
	if err != nil {
		return nil, err
	}
	creds := new(corev1.Secret)
	err = r.Client.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      *tgSpec.Config.CredentialName,
	}, creds)
	if err != nil {
		return nil, err
	}

	topts := []gnoiapi.TargetOption{
		gnoiapi.Name(tg.Name),
		gnoiapi.Address(*tgSpec.Config.Address),
		gnoiapi.Username(string(creds.Data["username"])),
		gnoiapi.Password(string(creds.Data["password"])),
	}
	if tgSpec.Config.Insecure != nil {
		topts = append(topts, gnoiapi.Insecure(*tgSpec.Config.Insecure))
	}
	if tgSpec.Config.SkipVerify != nil {
		topts = append(topts, gnoiapi.SkipVerify(*tgSpec.Config.SkipVerify))
	}
	return gnoiapi.NewTarget(topts...)
}

func (r *CertificateProfileReconciler) handleTarget(ctx context.Context, tg targetv1.Target, cp *yndddevv1alpha1.CertificateProfile) error {
	logger := r.Logger.WithValues(
		"certificate-profile", fmt.Sprintf("%s/%s", cp.GetNamespace(), cp.GetName()),
		"target", fmt.Sprintf("%s/%s", tg.GetNamespace(), tg.GetName()),
	)
	logger.Info("handling target")
	var err error
	// check if a certificate already exists
	cmCert := &certv1.Certificate{}
	err = r.Client.Get(ctx, types.NamespacedName{
		Namespace: cp.Namespace,
		// the certificate will have the same name as the certificate profile
		Name: fmt.Sprintf("%s-%s", cp.Name, tg.Name),
	}, cmCert)
	if err != nil {
		// certificate not found, create it
		if kerrors.IsNotFound(err) {
			logger.Debug("certificate not found, creating it")
			// TODO: create certificate request?
			cmCert = buildCertObj(*cp, tg)
			err = r.Client.Create(ctx, cmCert)
			if err != nil {
				logger.Info("failed to create certificate", "error", err)
				return err
			}
			logger.Info("created certificate", "certificate", cmCert)
			return nil
		}
		logger.Info("failed to get certificate", "error", err)
		return err
	}
	logger.Debug("found certificate", "certificate", cmCert)

	// certificate found, check secret
	secret := &corev1.Secret{}
	secretName := secretName(cp.GetName(), tg.GetName(), cp.Spec.Properties.SecretName)
	err = r.Client.Get(ctx, types.NamespacedName{
		Namespace: cmCert.Namespace,
		Name:      secretName,
	}, secret)
	if err != nil {
		logger.Info("failed to get secret", "error", err)
		return err
	}
	key := secret.Data["tls.key"]
	cert := secret.Data["tls.crt"]
	ca := secret.Data["ca.crt"]
	logger.Debug("got certificate", "key", key, "cert", cert, "ca", ca)
	logger.Debug("creating gNOI target")

	gnoiTarget, err := r.createGNOITarget(ctx, cmCert.Namespace, tg)
	if err != nil {
		return err
	}
	logger.Info("target config", "config", gnoiTarget.Config)
	ctx = metadata.AppendToOutgoingContext(ctx, "username", *gnoiTarget.Config.Username, "password", *gnoiTarget.Config.Password)
	err = gnoiTarget.CreateGrpcClient(ctx, grpc.WithBlock())
	if err != nil {
		return err
	}
	defer gnoiTarget.Close()
	logger.Debug("created gRPC client for gNOI")
	gNOICertClient := gnoiTarget.CertClient()
	// get installed certificates
	targetCertificates, err := gNOICertClient.GetCertificates(ctx, gnoicert.NewCertGetCertificatesRequest())
	if err != nil {
		return err
	}
	logger.Debug("target certificates", "certificates", targetCertificates)
	remoteCertificateName := cmCert.Labels["certificate-profile"]
	for _, remCert := range targetCertificates.GetCertificateInfo() {
		logger.Debug("existing certificate", "name", remCert.CertificateId)
		if remCert.CertificateId != remoteCertificateName {
			continue
		}
		// TODO: check if the certificate needs to be rotated
		// TODO: parse certificate and check expiry
		expiry := time.Unix(0, remCert.ModificationTime).Add(5 * time.Minute)
		if !time.Now().After(expiry) {
			logger.Info("certificate did not reach (fake) rotation time", "name", remCert.CertificateId)
			return nil // TODO: add error to requeue
		}
		logger.Debug("rotating certificate", "name", remCert.CertificateId)
		csr, err := r.getCertificateRequest(ctx,
			map[string]string{
				"certificate-profile": cp.GetName(),
				"target":              tg.GetName(),
			})
		if err != nil {
			return err
		}
		logger.Debug("found certificate request", "csr", csr)

		stream, err := gNOICertClient.Rotate(ctx)
		if err != nil {
			return err
		}
		rotateLoadCerReq, err := gnoicert.NewCertRotateLoadCertificateRequest(
			gnoicert.Certificate(
				gnoicert.CertificateType("CT_X509"),
				gnoicert.CertificateBytes(cert),
			),
			gnoicert.KeyPair(
				gnoicert.PublicKey(csr.Spec.Request),
				gnoicert.PrivateKey(key),
			),
			gnoicert.CertificateID(remoteCertificateName),
		)
		if err != nil {
			return err
		}
		err = stream.Send(rotateLoadCerReq)
		if err != nil {
			return err
		}
		rsp, err := stream.Recv()
		if err != nil {
			return err
		}
		logger.Debug("certificate rotate response", "response", rsp)
		logger.Debug("certificate rotate finalizing")
		err = stream.Send(gnoicert.NewCertRotateFinalizeRequest())
		if err != nil {
			return err
		}
		logger.Info("certificate rotate successful")
		return nil
	}
	// INSTALL
	logger.Debug("certificate does not exist on target, installing it")
	csr, err := r.getCertificateRequest(ctx,
		map[string]string{
			"certificate-profile": cp.GetName(),
			"target":              tg.GetName(),
		})
	if err != nil {
		return err
	}
	logger.Debug("found certificate request", "csr", csr)

	stream, err := gNOICertClient.Install(ctx)
	if err != nil {
		return err
	}
	req, err := gnoicert.NewCertInstallLoadCertificateRequest(
		gnoicert.Certificate(
			gnoicert.CertificateType("CT_X509"),
			gnoicert.CertificateBytes(cert),
		),
		gnoicert.KeyPair(
			gnoicert.PublicKey(csr.Spec.Request),
			gnoicert.PrivateKey(key),
		),
		gnoicert.CertificateID(remoteCertificateName),
	)
	if err != nil {
		return err
	}
	err = stream.Send(req)
	if err != nil {
		return err
	}
	rsp, err := stream.Recv()
	if err != nil {
		return err
	}
	logger.Debug("certificate install response", "response", rsp)
	logger.Info("certificate install successful")
	return nil
}

func (r *CertificateProfileReconciler) getCertificateRequest(ctx context.Context, selector map[string]string) (*certv1.CertificateRequest, error) {
	validatedLabels, err := labels.ValidatedSelectorFromSet(selector)
	if err != nil {
		return nil, err
	}
	csr := &certv1.CertificateRequestList{}
	err = r.Client.List(ctx, csr, &client.ListOptions{
		LabelSelector: validatedLabels,
		Limit:         1,
	})
	if err != nil {
		return nil, err
	}
	if len(csr.Items) == 0 {
		return nil, errors.New("certificate request not found")
	}
	return &csr.Items[0], nil
}

func secretName(cpName, targetName, secretName string) string {
	return fmt.Sprintf("%s-%s-%s", cpName, targetName, secretName)
}
