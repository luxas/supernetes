// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package vk

import (
	"context"
	"strconv"

	api "github.com/supernetes/supernetes/api/v1alpha1"
	"github.com/supernetes/supernetes/common/pkg/log"
	"github.com/virtual-kubelet/virtual-kubelet/node"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// instance represents a singular Virtual Kubelet node
type instance struct {
	tracked bool
	cancel  func()
}

func newInstance(k8sInterface kubernetes.Interface, n *api.Node) *instance {
	// TODO: This needs to be properly populated based on `n`
	nodeCfg := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   n.Meta.Name,
			Labels: map[string]string{"supernetes-node": "true"}, // TODO: Temporary, for easy kubectl filtering
		},
		Spec: corev1.NodeSpec{
			Taints: []corev1.Taint{{
				Key:    "supernetes-node/no-schedule",
				Value:  strconv.FormatBool(true),
				Effect: corev1.TaintEffectNoSchedule,
			}},
		},
		Status: corev1.NodeStatus{
			// NodeInfo: v1.NodeSystemInfo{
			// 	KubeletVersion:  Version,
			// 	Architecture:    architecture,
			// 	OperatingSystem: linuxos,
			// },
			//Addresses:       []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: internalIP}},
			//DaemonEndpoints: corev1.NodeDaemonEndpoints{KubeletEndpoint: corev1.DaemonEndpoint{Port: int32(daemonEndpointPort)}},
			Capacity: corev1.ResourceList{
				"cpu":    resource.MustParse("1"),
				"memory": resource.MustParse("1Gi"),
				"pods":   resource.MustParse("0"),
			},
			Allocatable: corev1.ResourceList{
				"cpu":    resource.MustParse("0"),
				"memory": resource.MustParse("0"),
				"pods":   resource.MustParse("0"),
			},
			//Conditions: nodeConditions(), // TODO: This needs to be dynamically synchronized
		},
	}

	// Set up node controller
	// TODO: Currently the node status is externally managed, but we could consider implementing `NodeProvider` here
	nodeProvider := &node.NaiveNodeProvider{}
	nodeRunner, err := node.NewNodeController(nodeProvider, nodeCfg, k8sInterface.CoreV1().Nodes())
	if err != nil {
		log.Err(err).Msgf("creating controller for node %q failed", n.Meta.Name)
		return nil
	}

	// Set up pod controller

	//podProvider := &podInterface{}
	//cacheTimeout := 10 * time.Second // TODO: Make configurable

	//podControllerCfg := node.PodControllerConfig{
	//	PodClient: k8sInterface.CoreV1(),
	//	// TODO: podInformer in client-go cannot be instantiated? Generator bug?
	//	//PodInformer:       corev1informers.NewPodInformer(k8sInterface, "", cacheTimeout, nil), // TODO: Implement, filter per-node here or use PodEventFilterFunc
	//	EventRecorder:     nil, // TODO: Implement
	//	Provider:          podProvider,
	//	ConfigMapInformer: nil, // TODO: Implement
	//	SecretInformer:    nil, // TODO: Implement
	//	ServiceInformer:   nil, // TODO: Implement
	//}

	//podRunner, err := node.NewPodController(podControllerCfg)
	//if err != nil {
	//	log.Err(err).Msgf("creating pod controller for %q failed", n.Meta.Name)
	//	return nil
	//}

	// TODO: Add timeout for detecting hangs? Go can't forcibly terminate goroutines
	ctx, cancel := context.WithCancel(context.Background())

	// Start controllers
	go func() {
		log.Debug().Msgf("starting controller for node %q", n.Meta.Name)
		if err := nodeRunner.Run(ctx); err != nil {
			log.Err(err).Msgf("running controller for node %q failed", n.Meta.Name)
			return
		}

		// TODO: We need to defer/handle node deletion here, Virtual Kubelet doesn't seem to do it automatically
		//  Normally, deletion of stale nodes after a timeout would normally be handled by the Cluster Autoscaler
		//  (https://github.com/kubernetes/autoscaler/tree/master/cluster-autoscaler), but this seems to heavily rely
		//  on cloud-provider-specific APIs and won't work with Talos
		// TODO: Maybe Supernetes should run another controller/reconciliation loop for handling virtual node pruning?
		// TODO: Another option is the Kyverno cleanup controller (https://kyverno.io/docs/writing-policies/cleanup/)

		log.Debug().Msgf("stopping controller for node %q", n.Meta.Name)
	}()

	// TODO: Implement
	//go func() {
	//	log.Debug().Msgf("starting pod controller for %q", n.Meta.Name)
	//	if err := podRunner.Run(ctx, 1); err != nil { // TODO: 1 worker per node?
	//		log.Err(err).Msgf("running pod controller for %q failed", n.Meta.Name)
	//		return
	//	}
	//
	//	log.Debug().Msgf("stopping pod controller for %q", n.Meta.Name)
	//}()

	return &instance{
		tracked: true, // Newly created instances are always tracked
		cancel:  cancel,
	}
}
