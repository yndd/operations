/*
Copyright 2021 NDD.
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

	//ndddvrv1 "github.com/yndd/ndd-core/apis/dvr/v1"
	certv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/yndd/ndd-runtime/pkg/logging"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type certificateHandler struct {
	client client.Client
	log    logging.Logger
}

// Create enqueues a request for all infrastructures which pertains to the topology.
func (e *certificateHandler) Create(evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	e.add(evt.Object, q)
}

// Create enqueues a request for all infrastructures which pertains to the topology.
func (e *certificateHandler) Update(evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	e.add(evt.ObjectOld, q)
	e.add(evt.ObjectNew, q)
}

// Create enqueues a request for all infrastructures which pertains to the topology.
func (e *certificateHandler) Delete(evt event.DeleteEvent, q workqueue.RateLimitingInterface) {
	e.add(evt.Object, q)
}

// Create enqueues a request for all infrastructures which pertains to the topology.
func (e *certificateHandler) Generic(evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	e.add(evt.Object, q)
}

func (e *certificateHandler) add(obj runtime.Object, queue adder) {
	cert, ok := obj.(*certv1.Certificate)
	if !ok || cert == nil {
		return
	}
	log := e.log.WithValues("function", "watch certificate", "name", cert.GetName())

	targetName, ok := cert.GetAnnotations()["target"]
	if !ok {
		return
	}
	// _, ok = cert.GetAnnotations()["operations"]
	// if !ok {
	// 	return
	// }
	certProfName, ok := cert.GetAnnotations()["certificate-profile"]
	if !ok {
		return
	}
	if targetName == "" || certProfName == "" {
		return
	}
	namespace := cert.GetNamespace()
	// found certificate profile, queue it
	log.Debug("found certificate profile", "certificate-profile", certProfName)
	queue.Add(reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: namespace,
			Name:      certProfName,
		}})

}

type adder interface {
	Add(item interface{})
}
