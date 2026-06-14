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
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cclab-inu/KubeTeus/pkg/enforcer"
	"github.com/cclab-inu/KubeTeus/pkg/policygenerator"
	//"github.com/cclab-inu/KubeTeus/pkg/promptprocessor"
	"github.com/cclab-inu/KubeTeus/pkg/tester"
	"github.com/cclab-inu/KubeTeus/pkg/utils"
	"github.com/cclab-inu/KubeTeus/pkg/validator"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
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

	Model         string
	Mode          string
	Intent        *string
	Queue         *utils.IntentQueue
	TestNamespace string

	startTime    time.Time
	HTTPClient   *http.Client
	podInfoCache []utils.PodDiscoveryInfo
}

func (r *KubeTeusReconciler) SetIntent(intent string) {
	*r.Intent = intent
	r.Reconcile(context.TODO(), ctrl.Request{})
}

func (r *KubeTeusReconciler) EnqueueIntent(intent string) (bool, error) {
	ok := r.Queue.Push(intent)
	if !ok {
		return false, fmt.Errorf("queue is full (max 50 intents)")
	}
	return true, nil
}

// Avviato come goroutine in SetupWithManager
func (r *KubeTeusReconciler) runQueueWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case intent := <-r.Queue.Ch: // <-- Ch maiuscola
			reqCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			r.processIntent(reqCtx, intent)
			cancel()
		}
	}
}

func (r *KubeTeusReconciler) refreshPodInfoCache(ctx context.Context) {
	logger := log.FromContext(ctx)
	info, err := r.discoverPodInfo(ctx)
	if err != nil {
		logger.Error(err, "failed to refresh pod info cache")
		return
	}
	r.podInfoCache = info
	logger.Info("Pod info cache refreshed", "pods", len(info))
}

func (r *KubeTeusReconciler) processIntent(ctx context.Context, intent string) {
	logger := log.FromContext(ctx)

	servicesContext, err := r.getClusterServices(ctx)
	if err != nil {
		logger.Error(err, "failed to get cluster services")
		return
	}

	podInfoList := r.podInfoCache
	if len(podInfoList) == 0 {
		logger.Info("Pod info cache not ready yet, discovering now...")
		discovered, err := r.discoverPodInfo(ctx)
		if err == nil {
			r.podInfoCache = discovered
			podInfoList = discovered
		}
	}

	cniType, err := detectCNIPlugin(ctx, r.Client)
	if err != nil {
		logger.Error(err, "failed to detect CNI")
		return
	}

	var finalPrompt string
	switch cniType {
	case "cilium":
		finalPrompt = fmt.Sprintf("%s\n%s\nNamespace: %s\nGenerate a CiliumNetworkPolicy in namespace %s.",
			intent, servicesContext, r.TestNamespace, r.TestNamespace)
	case "calico":
		apiVersion := detectCalicoAPIVersion(ctx, r.Client)
		finalPrompt = fmt.Sprintf("%s\n%s\nNamespace: %s\nGenerate a CalicoNetworkPolicy with apiVersion: %s in namespace %s.",
			intent, servicesContext, r.TestNamespace, apiVersion, r.TestNamespace)
	default:
		finalPrompt = fmt.Sprintf("%s\n%s\nNamespace: %s\nGenerate a Kubernetes NetworkPolicy in namespace %s.",
			intent, servicesContext, r.TestNamespace, r.TestNamespace)
	}

	var prompts utils.Prompt
	prompts.Network = append(prompts.Network, finalPrompt)

	// Passa le info di discovery al server per la generazione dello script di test
	if len(podInfoList) > 0 {
		prompts.PodDiscovery = podInfoList // vedi nota sotto su utils.Prompt
	}

	var policies utils.Policy
	for i := 0; i < maxRetries; i++ {
		policies, err = policygenerator.PolicyGenerator(ctx, r.Client, r.Model, prompts)
		if err == nil && len(policies.Network) > 0 {
			break
		}
		logger.Info("Policy generation attempt failed, retrying", "attempt", i+1, "error", err)
		time.Sleep(retryInterval)
	}
	if err != nil || len(policies.Network) == 0 {
		logger.Error(err, "failed to generate policies after retries")
		return
	}

	logger.Info("Policies generated", "count", len(policies.Network))

	var podInfo utils.NetInfo
	var entities []utils.Entity
	validationErrors, err := validator.Validator(ctx, r.Client, logger, podInfo, entities, policies.Network)
	if err != nil {
		logger.Error(err, "Validator error")
		return
	}
	if len(validationErrors) > 0 {
		errStr := fmt.Sprintf("%v", validationErrors)
		logger.Error(fmt.Errorf("policy validation failed"), "Invalid configurations detected", "Errors", errStr)
		return
	}

	if err = enforcer.Enforcer(ctx, r.Client, policies.Network); err != nil {
		logger.Error(err, "failed to enforce policy")
		return
	}
	logger.Info("Policies enforced")

	if policies.TestScript != "" {
		output, err := tester.RunTestScript(ctx, policies.TestScript)
		if err != nil {
			logger.Info("Tests FAILED — rolling back")
			if rollbackErr := enforcer.Rollback(ctx, r.Client, policies.Network); rollbackErr != nil {
				logger.Error(rollbackErr, "Rollback failed")
			} else {
				logger.Info("Rollback completed")
			}
		} else {
			logger.Info("Tests passed", "output", output)
		}
	} else {
		logger.Info("No test script, skipping tests")
	}
}

func (r *KubeTeusReconciler) discoverPodInfo(ctx context.Context) ([]utils.PodDiscoveryInfo, error) {
	podList := &v1.PodList{}
	if err := r.List(ctx, podList); err != nil {
		return nil, err
	}

	var result []utils.PodDiscoveryInfo

	for _, pod := range podList.Items {
		// Salta i pod non Running
		if pod.Status.Phase != v1.PodRunning {
			continue
		}

		info := utils.PodDiscoveryInfo{
			Name:      pod.Name,
			Namespace: pod.Namespace,
			Labels:    pod.Labels,
		}

		// Raccogli porte e protocolli da tutti i container
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				proto := string(port.Protocol)
				if proto == "" {
					proto = "TCP"
				}
				info.Ports = append(info.Ports, utils.PortInfo{
					Port:     port.ContainerPort,
					Protocol: proto,
				})
			}
		}

		// Scopri tool disponibili eseguendo un comando nel pod
		tools := r.detectAvailableTools(ctx, pod)
		info.AvailableTools = tools
		//fmt.Printf("Pod %s tools: %v\n", pod.Name, tools)

		result = append(result, info)
	}
	fmt.Printf("Discovery result: %+v\n", result)
	return result, nil
}

// detectAvailableTools prova a eseguire 'which <tool>' nel primo container del pod.
func (r *KubeTeusReconciler) detectAvailableTools(ctx context.Context, pod v1.Pod) []string {
	candidates := []string{"curl", "wget", "nc", "ncat", "nmap", "ping", "telnet", "openssl", "bash", "sh"}
	var found []string

	if len(pod.Spec.Containers) == 0 {
		return found
	}
	containerName := pod.Spec.Containers[0].Name

	for _, tool := range candidates {
		out, err := ExecInPod(ctx, r.Client, pod.Namespace, pod.Name, containerName, []string{"which", tool})
		if err == nil && strings.TrimSpace(out) != "" {
			found = append(found, tool)
		}
	}
	return found
}

func ExecInPod(ctx context.Context, c client.Client, namespace, podName, containerName string, command []string) (string, error) {
	restConfig, err := config.GetConfig()
	if err != nil {
		return "", err
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return "", err
	}

	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&v1.PodExecOptions{
			Container: containerName,
			Command:   command,
			Stdout:    true,
			Stderr:    false,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &buf})
	return buf.String(), err
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

		// Find cluster services
		servicesContext, err := r.getClusterServices(ctx)
		if err != nil {
			logger.Error(err, "failed to get cluster services")
			return reconcile.Result{}, err
		}

		// Find the CNI
		cniType, err := detectCNIPlugin(ctx, r.Client)
		if err != nil {
			logger.Error(err, "failed to detect CNI")
			return reconcile.Result{}, err
		}

		// Build the final prompt
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
	}
	logger.Info("Prompts created") //, "Network Prompts", prompts.Network)
	if len(prompts.Network) == 0 {
		logger.Error(fmt.Errorf("no prompts generated"), "empty prompt pipeline")
		return doNotRequeue()
	}

	for i := 0; i < maxRetries; i++ {
		policies, err = policygenerator.PolicyGenerator(ctx, r.Client, r.Model, prompts)
		if err == nil && len(policies.Network) > 0 {
			break
		}
		logger.Info("Policy generation attempt failed, retrying",
			"attempt", i+1, "maxRetries", maxRetries, "error", err)
		time.Sleep(retryInterval)
	}
	if err != nil {
		logger.Error(err, "failed to execute policy creation after retries")
		return doNotRequeue()
	}
	if policies.Network == nil || len(policies.Network) == 0 {
		logger.Error(err, "no valid policies generated after retries")
		return doNotRequeue()
	}

	logger.Info("Policies generated", "Network Policies", policies.Network)

	validationErrors, err := validator.Validator(ctx, r.Client, logger, podInfo, entities, policies.Network)
	if err != nil {
		logger.Error(err, "Validator error — likely API server issue")
		return requeueWithError(err)
	}
	if len(validationErrors) > 0 {
		logger.Error(fmt.Errorf("policy validation failed"), "Identified a misconfiguration of Policy", "errors", validationErrors)
		return doNotRequeue()
	}
	logger.Info("Policies verified", "ValidationErrors.Count", len(validationErrors), "Policy.Details", policies.Network)

	if err = enforcer.Enforcer(ctx, r.Client, policies.Network); err != nil {
		logger.Error(err, "failed to enforce policy")
		return requeueWithError(err)
	}
	logger.Info("Policies enforeced")

	if policies.TestScript != "" {
		output, err := tester.RunTestScript(ctx, policies.TestScript)
		if err != nil {
			logger.Info("Post-enforcement tests FAILED — rolling back policies")

			if rollbackErr := enforcer.Rollback(ctx, r.Client, policies.Network); rollbackErr != nil {
				logger.Error(rollbackErr, "Rollback also failed — cluster may be in inconsistent state")
			} else {
				logger.Info("Rollback completed successfully")
			}
		} else {
			logger.Info("Post-enforcement testing completed", "test_output", output)
		}
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
	r.Queue = utils.NewIntentQueue(50)

	ctx := context.Background() // oppure passa il ctx del manager se disponibile
	r.refreshPodInfoCache(ctx)

	go func() {
		ticker := time.NewTicker(100 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.refreshPodInfoCache(ctx)
			}
		}
	}()

	go r.runQueueWorker(ctx)

	go func() {
		srv := &http.Server{
			Addr:         ":9090",
			ReadTimeout:  5 * time.Minute,
			WriteTimeout: 6 * time.Minute,
			IdleTimeout:  60 * time.Second,
		}

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

			ok, err := r.EnqueueIntent(strings.TrimSpace(string(body)))
			fmt.Printf("Intent: %s\n", body)
			if !ok {
				http.Error(w, fmt.Sprintf("Queue full: %v", err), http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			fmt.Fprintf(w, "Intent enqueued. Queue length: %d/50\n", len(r.Queue.Ch))
		})

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("HTTP server error: %v\n", err)
		}
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
	crdList := &apiextensionsv1.CustomResourceDefinitionList{}
	if err := k8sClient.List(ctx, crdList); err == nil {
		for _, crd := range crdList.Items {
			name := strings.ToLower(crd.Name)
			if strings.Contains(name, "cilium.io") {
				fmt.Printf("[DEBUG detectCNI] Found Cilium CRD: %s\n", crd.Name)
				return "cilium", nil
			}
			if strings.Contains(name, "projectcalico.org") ||
				strings.Contains(name, "crd.projectcalico.org") {
				fmt.Printf("[DEBUG detectCNI] Found Calico CRD: %s\n", crd.Name)
				return "calico", nil
			}
		}
	}

	podList := &v1.PodList{}
	if err := k8sClient.List(ctx, podList); err != nil {
		return "", err
	}
	for _, pod := range podList.Items {
		name := strings.ToLower(pod.Name)
		ns := pod.Namespace
		switch {
		case strings.Contains(name, "cilium"):
			fmt.Printf("[DEBUG detectCNI] Found Cilium pod: %s ns=%s\n", pod.Name, ns)
			return "cilium", nil
		case strings.Contains(name, "calico") ||
			ns == "calico-system" ||
			ns == "tigera-operator":
			fmt.Printf("[DEBUG detectCNI] Found Calico pod: %s ns=%s\n", pod.Name, ns)
			return "calico", nil
		}
	}

	fmt.Printf("[DEBUG detectCNI] No CNI detected\n")
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
