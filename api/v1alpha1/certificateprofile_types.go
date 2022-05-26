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

package v1alpha1

import (
	certv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// CertificateProfileSpec defines the desired state of CertificateProfile
type CertificateProfileSpec struct {
	// CertificateProfile Name
	Name string `json:"name,omitempty"`
	// TargetSelector specifies the targets for which this certificate profile needs to generate certificates
	// +optional
	TargetSelector *TargetSelector `json:"target-selector,omitempty"`

	//+kubebuilder:pruning:PreserveUnknownFields
	//+kubebuilder:validation:Required
	Properties certv1.CertificateSpec `json:"properties,omitempty"`
	//
	// Ciphers []string `json:"ciphers,omitempty"`
}

// CertificateProfileStatus defines the observed state of CertificateProfile
type CertificateProfileStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// CertificateProfile is the Schema for the certificateprofiles API
type CertificateProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateProfileSpec   `json:"spec,omitempty"`
	Status CertificateProfileStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// CertificateProfileList contains a list of CertificateProfile
type CertificateProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertificateProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CertificateProfile{}, &CertificateProfileList{})
}

type TargetSelector struct {
	//
	Namespace string `json:"namespace,omitempty"`
	// Labels is a key value map to be used for target CR selection.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// Annotations is a key value map to be used for target CR selection.
	// +optional
	// Annotations map[string]string `json:"annotations,omitempty"`
}
