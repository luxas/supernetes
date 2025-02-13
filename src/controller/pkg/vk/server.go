// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package vk

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/supernetes/supernetes/common/pkg/log"
	"github.com/supernetes/supernetes/common/pkg/supernetes"
	"github.com/supernetes/supernetes/controller/pkg/server/certificates"
	vkauth "github.com/supernetes/supernetes/controller/pkg/vk/auth"
	vkapi "github.com/virtual-kubelet/virtual-kubelet/node/api"
	"github.com/virtual-kubelet/virtual-kubelet/node/nodeutil"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/component-base/cli/flag"
)

var errServingCertTimeout = errors.New("timeout waiting for kubelet serving certificate")

// KubeletServer provides the Kubelet HTTP functionality for a Virtual Kubelet instance
type KubeletServer struct {
	kubeClient    kubernetes.Interface
	handler       vkapi.PodHandlerConfig
	vkAuth        vkauth.Auth
	nodeName      string
	nodeAddresses func() []v1.NodeAddress
	port          atomic.Int32
	ready         chan struct{}
}

func NewKubeletServer(kubeClient kubernetes.Interface, handler vkapi.PodHandlerConfig, vkAuth vkauth.Auth, nodeName string, nodeAddresses func() []v1.NodeAddress) *KubeletServer {
	return &KubeletServer{
		kubeClient:    kubeClient,
		handler:       handler,
		vkAuth:        vkAuth,
		nodeName:      nodeName,
		nodeAddresses: nodeAddresses,
		ready:         make(chan struct{}),
	}
}

func (s *KubeletServer) Run(ctx context.Context) (err error) {
	// Create a listener for the server letting the OS pick a free port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return err
	}

	// Close the listener when stopped
	defer func() {
		_ = listener.Close()
	}()

	// Acquire the allocated port number
	port := listener.Addr().(*net.TCPAddr).Port

	// Start a Kubelet server certificate manager tailored to the VK instance
	mgr, err := certificates.NewKubeletServerCertificateManager(
		s.kubeClient, types.NodeName(s.nodeName),
		s.nodeAddresses,
		supernetes.CertsDir,
	)
	if err != nil {
		return err
	}

	log.Trace().Msg("starting kubelet serving certificate manager")
	mgr.Start() // Non-blocking
	defer mgr.Stop()

	mgrCtx, cancel := context.WithTimeoutCause(ctx, 30*time.Second, errServingCertTimeout)
	defer cancel()

	log.Trace().Msg("waiting for kubelet serving certificate")
	err = wait.PollUntilContextCancel(mgrCtx, time.Second, true, func(ctx context.Context) (done bool, err error) {
		return mgr.Current() != nil, nil
	})
	if err != nil {
		return err
	}

	apiHandler := http.NewServeMux()
	apiHandler.Handle("/", vkapi.PodHandler(s.handler, false))

	vkAuth, err := s.vkAuth.VkAuth(s.nodeName)
	if err != nil {
		return err
	}

	srv := &http.Server{
		IdleTimeout:  90 * time.Second,                      // kubelet option, matches http.DefaultTransport keep-alive timeout TODO: source directly
		ReadTimeout:  4 * 60 * time.Minute,                  // kubelet option TODO: source directly
		WriteTimeout: 4 * 60 * time.Minute,                  // kubelet option TODO: source directly
		Handler:      nodeutil.WithAuth(vkAuth, apiHandler), // TODO: instrumentation
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequestClientCert,    // mTLS, also enabled by kubelet
			MinVersion: flag.DefaultTLSVersion(), // As per kubelet default
			GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return mgr.Current(), nil
			},
			// TODO: This doesn't support rotation, but the CA is seemingly valid for 10 years by default
			ClientCAs: s.vkAuth.ClientCAPool(),
		},
	}

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	s.port.Store(int32(port)) // Update port number
	close(s.ready)            // Mark readiness
	return srv.ServeTLS(listener, "", "")
}

func (s *KubeletServer) Port() int32 {
	return s.port.Load()
}

func (s *KubeletServer) Ready() <-chan struct{} {
	return s.ready
}
