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

	"github.com/yndd/ndd-runtime/pkg/logging"
	targetv1 "github.com/yndd/ndd-target-runtime/apis/dvr/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type targetHandler struct {
	client client.Client
	log    logging.Logger
}

// Create enqueues a request for all infrastructures which pertains to the topology.
func (e *targetHandler) Create(evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	e.add(evt.Object, q)
}

// Create enqueues a request for all infrastructures which pertains to the topology.
func (e *targetHandler) Update(evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	e.add(evt.ObjectOld, q)
	e.add(evt.ObjectNew, q)
}

// Create enqueues a request for all infrastructures which pertains to the topology.
func (e *targetHandler) Delete(evt event.DeleteEvent, q workqueue.RateLimitingInterface) {
	e.add(evt.Object, q)
}

// Create enqueues a request for all infrastructures which pertains to the topology.
func (e *targetHandler) Generic(evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	e.add(evt.Object, q)
}

func (e *targetHandler) add(obj runtime.Object, queue adder) {
	tg, ok := obj.(*targetv1.Target)
	if !ok || tg == nil {
		return
	}
	log := e.log.WithValues("function", "watch target", "target", tg.GetName())
	certProfName, ok := tg.GetLabels()["yndd.io/certificate-profile"]
	if !ok || certProfName == "" {
		return
	}
	namespace := tg.GetNamespace()
	log.Debug("found certificate profile", "certificate-profile", certProfName)
	// found certificate profile, queue it
	queue.Add(reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: namespace,
			Name:      certProfName,
		}})
}
