/*
Copyright 2025.

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

package controller

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cclab-inu/KubeTeus/pkg/enforcer"
	"github.com/cclab-inu/KubeTeus/pkg/policygenerator"
	//"github.com/cclab-inu/KubeTeus/pkg/promptprocessor"
	"github.com/cclab-inu/KubeTeus/pkg/tester"
	"github.com/cclab-inu/KubeTeus/pkg/utils"
	"github.com/cclab-inu/KubeTeus/pkg/validator"
	"github.com/cclab-inu/KubeTeus/pkg/watcher"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	maxRetries    = 3
	retryInterval = 2 * time.Second
)

// KubeTeusReconciler reconciles a KubeTeus object
type KubeTeusReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Model  string
	Mode   string
	Intent *string

	startTime  time.Time
	HTTPClient *http.Client
}

func (r *KubeTeusReconciler) SetIntent(intent string) {
	*r.Intent = intent
	r.Reconcile(context.TODO(), ctrl.Request{})
}

// +kubebuilder:rbac:groups=policy,resources=kubeteuses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=policy,resources=kubeteuses/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=policy,resources=kubeteuses/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the KubeTeus object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.4/pkg/reconcile
func (r *KubeTeusReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	//var finalIntent []string
	var prompts utils.Prompt
	var policies utils.Policy
	var podInfo utils.NetInfo
	var entities []utils.Entity
	var err error
	if r.Mode == "user" && r.Intent != nil && *r.Intent != "" {
		logger.Info("Using raw intent (LLM-based pipeline)")

		// 🔹 1. Recupera servizi dal cluster
		servicesContext, err := r.getClusterServices(ctx)
		if err != nil {
			logger.Error(err, "failed to get cluster services")
			return reconcile.Result{}, err
		}

		// 🔹 2. Recupera CNI
		cniType, err := detectCNIPlugin(ctx, r.Client)
		if err != nil {
			logger.Error(err, "failed to detect CNI")
			return reconcile.Result{}, err
		}

		// 🔹 3. Costruisci prompt finale
		var finalPrompt string

		switch cniType {
		case "cilium":
			finalPrompt = fmt.Sprintf("%s\n%s\nGenerate a CiliumNetworkPolicy.", *r.Intent, servicesContext)
		case "calico":
			apiVersion := detectCalicoAPIVersion(ctx, r.Client)
			finalPrompt = fmt.Sprintf("%s\n%s\nGenerate a CalicoNetworkPolicy with apiVersion: %s.", *r.Intent, servicesContext, apiVersion)
		default:
			finalPrompt = fmt.Sprintf("%s\n%s\nGenerate a Kubernetes NetworkPolicy.", *r.Intent, servicesContext)
		}

		prompts.Network = append(prompts.Network, finalPrompt)
	} else if r.Mode == "user" && (r.Intent == nil || *r.Intent == "") {
		logger.Info("Intent not found")
		return doNotRequeue()
	} else if r.Mode == "config" {
		var yamlInfo utils.YAMLInfo
		resourceFound := false

		pod := &v1.Pod{}
		err := r.Get(ctx, req.NamespacedName, pod)
		if err != nil {
			if errors.IsNotFound(err) {
				logger.Info("Resource Deleted")
				return doNotRequeue()
			}
			logger.Error(err, "failed to fetch Resource")
			return requeueWithError(err)
		} else {
			resourceFound = true
		}

		if !resourceFound {
			select {
			case <-time.After(3 * time.Second):
				resourceFiles, err := filepath.Glob("resource/*.yaml")
				if err != nil {
					logger.Error(err, "failed to read resource folder")
					return reconcile.Result{}, err
				}
				if len(resourceFiles) > 0 {
					resourceFile := resourceFiles[0]
					content, err := os.ReadFile(resourceFile)
					if err != nil {
						logger.Error(err, "failed to read resource file")
						return reconcile.Result{}, err
					}
					if err := yaml.Unmarshal(content, &yamlInfo); err != nil {
						logger.Error(err, "failed to unmarshal yaml file")
						return reconcile.Result{}, err
					}
					req.NamespacedName.Namespace = yamlInfo.Namespace
					req.NamespacedName.Name = yamlInfo.Name
					resourceFound = true
				} else {
					logger.Info("No resource file found")
					return doNotRequeue()
				}
			}
		}

		if resourceFound {
			logger.Info("Resource Found", "Model", r.Model)

			// Fetch pod configuration using the GetConfig function from the watcher package
			netInfo, err := watcher.GetConfig(ctx, r.Client, req.NamespacedName.Namespace, req.NamespacedName.Name)
			if err != nil {
				logger.Error(err, "failed to get configuration")
				return reconcile.Result{}, err
			}
			logger.Info("Information Extraction Completed", "NetInfo", netInfo)

			/*prompts, err = promptprocessor.ConfigPromptBuilder(ctx, r.Client, netInfo)
			if err != nil {
				logger.Error(err, "failed to build prompts")
				return reconcile.Result{}, err
			}*/
		}
	}
	logger.Info("Prompts created", "Network Prompts", prompts.Network)
	if len(prompts.Network) == 0 {
		logger.Error(fmt.Errorf("no prompts generated"), "empty prompt pipeline")
		return ctrl.Result{}, fmt.Errorf("no prompts generated")
	}

	for i := 0; i < maxRetries; i++ {
		policies, err = policygenerator.PolicyGenerator(ctx, r.Client, r.Model, prompts)
		if err == nil {
			break
		}
		if policies.Network == nil || len(policies.Network) == 0 {
			logger.Error(fmt.Errorf("empty policies"), "LLM returned no policies", "attempt", i+1)
			time.Sleep(retryInterval)
			continue
		}

		logger.Error(err, "failed to execute policy creation, retrying...", "attempt", i+1, "maxRetries", maxRetries)
		time.Sleep(retryInterval)
	}
	if err != nil {
		logger.Error(err, "failed to execute policy creation after retries")
		return ctrl.Result{}, err
	}
	if policies.Network == nil || len(policies.Network) == 0 {
		return ctrl.Result{}, fmt.Errorf("no valid policies generated after retries")
	}

	logger.Info("Policies generated", "Network Policies", policies.Network)

	validationErrors, err := validator.Validator(ctx, r.Client, logger, podInfo, entities, policies.Network)
	if err != nil {
		return requeueWithError(err)
	}
	if len(validationErrors) > 0 {
		logger.Info("Identified a misconfiguration of Policy", "ValidationErrors", validationErrors)
		return doNotRequeue()
	}
	logger.Info("Policies verified", "ValidationErrors.Count", len(validationErrors), "Policy.Details", policies.Network)

	if err = enforcer.Enforcer(ctx, r.Client, policies.Network); err != nil {
		logger.Error(err, "failed to enforce policy")
		return doNotRequeue()
	}
	logger.Info("Policies enforeced")

	if policies.TestScript != "" {
		output, err := tester.RunTestScript(ctx, policies.TestScript)
		if err != nil {
			logger.Error(err, "Post-enforcement tests FAILED — rolling back policies",
				"test_output", output)

			if rollbackErr := enforcer.Rollback(ctx, r.Client, policies.Network); rollbackErr != nil {
				logger.Error(rollbackErr, "Rollback also failed — cluster may be in inconsistent state")
			} else {
				logger.Info("Rollback completed successfully")
			}
			return doNotRequeue()
		}
		logger.Info("Post-enforcement testing completed", "test_output", output)
	} else {
		logger.Info("No test script available, skipping connectivity tests")
	}

	return doNotRequeue()
}

// StartPredicate filters events based on t dhe start time of the controller.
func StartPredicate(startTime time.Time) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return e.Object.GetCreationTimestamp().After(startTime)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return e.ObjectNew.GetCreationTimestamp().After(startTime)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return e.Object.GetCreationTimestamp().After(startTime)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return e.Object.GetCreationTimestamp().After(startTime)
		},
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *KubeTeusReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.startTime = time.Now()

	go func() {
		http.HandleFunc("/intent", func(w http.ResponseWriter, req *http.Request) {
			if req.Method != "POST" {
				http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
				return
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				http.Error(w, "Error reading intent", http.StatusInternalServerError)
				return
			}
			defer req.Body.Close()

			r.SetIntent(string(body))
		})
		http.ListenAndServe(":9090", nil)
	}()

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Pod{}, builder.WithPredicates(StartPredicate(r.startTime))).
		Owns(&appsv1.Deployment{}, builder.WithPredicates(StartPredicate(r.startTime))).
		Owns(&v1.Service{}, builder.WithPredicates(StartPredicate(r.startTime))).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Named("kubeteus").
		Complete(r)
}

func detectCNIPlugin(ctx context.Context, k8sClient client.Client) (string, error) {
	podList := &v1.PodList{}
	if err := k8sClient.List(ctx, podList, client.InNamespace("kube-system")); err != nil {
		return "", err
	}

	for _, pod := range podList.Items {
		name := strings.ToLower(pod.Name)
		switch {
		case strings.Contains(name, "cilium"):
			return "cilium", nil
		case strings.Contains(name, "calico"):
			return "calico", nil
		case strings.Contains(name, "antrea"):
			return "antrea", nil
		case strings.Contains(name, "weave"):
			return "weave", nil
		}
	}
	return "unknown", nil
}

func detectCalicoAPIVersion(ctx context.Context, k8sClient client.Client) string {
	// Search calico's CDR and read group and version
	exec := func(group, version string) bool {
		u := &unstructured.UnstructuredList{}
		u.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   group,
			Version: version,
			Kind:    "NetworkPolicyList",
		})
		err := k8sClient.List(ctx, u, client.InNamespace("default"))
		return err == nil
	}
	if exec("crd.projectcalico.org", "v1") {
		return "crd.projectcalico.org/v1"
	}
	if exec("projectcalico.org", "v3") {
		return "projectcalico.org/v3"
	}
	return "crd.projectcalico.org/v1"
}

func (r *KubeTeusReconciler) getClusterServices(ctx context.Context) (string, error) {
	var svcList v1.ServiceList

	err := r.List(ctx, &svcList)
	if err != nil {
		return "", err
	}

	services := "Available services in the cluster:\n"

	for _, svc := range svcList.Items {
		services += fmt.Sprintf("- %s\n", svc.Name)
	}

	return services, nil
}
