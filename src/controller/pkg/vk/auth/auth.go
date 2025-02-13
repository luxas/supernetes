// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package auth

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/supernetes/supernetes/common/pkg/log"
	"github.com/supernetes/supernetes/common/pkg/supernetes"
	"github.com/virtual-kubelet/virtual-kubelet/node/nodeutil"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/client-go/kubernetes"
)

var errCaTimeout = errors.New("timeout waiting for API server CA")

type Auth interface {
	VkAuth(nodeName string) (nodeutil.Auth, error)
	ClientCAPool() *x509.CertPool
}

type auth struct {
	kubeClient   kubernetes.Interface
	apiServerCa  dynamiccertificates.CAContentProvider
	clientCaPool *x509.CertPool
}

func Start(ctx context.Context, kubeClient kubernetes.Interface) (Auth, error) {
	// TODO: RBAC rules to get configmap
	apiServerCa, err := dynamiccertificates.NewDynamicCAFromConfigMapController("client-ca", supernetes.NamespaceWorkload, "kube-root-ca.crt", "ca.crt", kubeClient)
	if err != nil {
		return nil, err
	}
	go apiServerCa.Run(ctx, 1)

	caCtx, cancel := context.WithTimeoutCause(ctx, 30*time.Second, errCaTimeout)
	defer cancel()

	log.Trace().Msg("waiting for API server CA")
	err = wait.PollUntilContextCancel(caCtx, time.Second, true, func(ctx context.Context) (done bool, err error) {
		return apiServerCa.CurrentCABundleContent() != nil, nil
	})
	if err != nil {
		return nil, err
	}

	clientCaPool := x509.NewCertPool()
	if ok := clientCaPool.AppendCertsFromPEM(apiServerCa.CurrentCABundleContent()); !ok {
		return nil, fmt.Errorf("couldn't parse API server CA: %s", string(apiServerCa.CurrentCABundleContent()))
	}

	return &auth{
		kubeClient:   kubeClient,
		apiServerCa:  apiServerCa,
		clientCaPool: clientCaPool,
	}, nil
}

func (a *auth) VkAuth(nodeName string) (nodeutil.Auth, error) {
	return nodeutil.WebhookAuth(a.kubeClient, nodeName, func(wac *nodeutil.WebhookAuthConfig) error {
		wac.AuthnConfig.ClientCertificateCAContentProvider = a.apiServerCa
		return nil
	})
}

func (a *auth) ClientCAPool() *x509.CertPool {
	return a.clientCaPool
}
