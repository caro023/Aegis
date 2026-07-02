package validator

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func ResourceValidator(ctx context.Context, k8sClient client.Client, logger logr.Logger, policies interface{}) []error {
	var errs []error

	// Convert []string in []interface{} if necessary
	var policySlice []interface{}
	switch v := policies.(type) {
	case []string:
		for _, s := range v {
			policySlice = append(policySlice, s)
		}
	case []interface{}:
		policySlice = v
	}
	for _, policy := range policySlice {
		policyMap, err := toMap(policy)
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid policy type: %v", err))
			continue
		}

		kind, ok := policyMap["kind"].(string)
		if !ok {
			errs = append(errs, fmt.Errorf("missing or invalid kind in policy"))
			continue
		}

		metadata, ok := policyMap["metadata"].(map[string]interface{})
		if !ok {
			errs = append(errs, fmt.Errorf("missing or invalid metadata in policy"))
			continue
		}

		spec, ok := policyMap["spec"].(map[string]interface{})
		if !ok {
			errs = append(errs, fmt.Errorf("missing or invalid spec in policy"))
			continue
		}

		var labelMap map[string]string

		if kind == "CiliumNetworkPolicy" {
			// CILIUM
			selector, ok := spec["endpointSelector"].(map[string]interface{})
			if !ok {
				errs = append(errs, fmt.Errorf("missing endpointSelector in Cilium policy"))
				continue
			}

			matchLabels, ok := selector["matchLabels"].(map[string]interface{})
			if !ok {
				errs = append(errs, fmt.Errorf("missing matchLabels in Cilium policy"))
				continue
			}

			labelMap = make(map[string]string)
			for key, value := range matchLabels {
				cleanKey := strings.TrimPrefix(key, "any:")
				labelMap[cleanKey] = value.(string)
			}

		} else if kind == "NetworkPolicy" {
			// Distinguish between Calico (projectcalico.org/v3) and standard NetworkPolicy
			apiVersion, _ := policyMap["apiVersion"].(string)
			if strings.Contains(apiVersion, "calico") || strings.Contains(apiVersion, "projectcalico") {
				// CALICO - use selector string, skip label validation
				labelMap = map[string]string{}
				logger.Info("Calico policy detected, skipping label validation")
			} else {
				// NetworkPolicy standard Kubernetes
				selector, ok := spec["podSelector"].(map[string]interface{})
				if !ok {
					errs = append(errs, fmt.Errorf("missing podSelector in NetworkPolicy"))
					continue
				}
				matchLabels, _ := selector["matchLabels"].(map[string]interface{})
				labelMap = make(map[string]string)
				for key, value := range matchLabels {
					labelMap[key] = fmt.Sprintf("%v", value)
				}
			}
		} else {
			errs = append(errs, fmt.Errorf("unsupported policy kind: %s", kind))
			continue
		}

		// namespace
		namespace, ok := metadata["namespace"].(string)
		if !ok {
			errs = append(errs, fmt.Errorf("missing or invalid namespace in policy"))
			continue
		}

		// validate namespace
		err = validateNamespaces(ctx, k8sClient, namespace)
		if err != nil {
			errs = append(errs, err)
		}

		err = validateNamespaceStatus(ctx, k8sClient, namespace)
		if err != nil {
			errs = append(errs, err)
		}

		if len(labelMap) > 0 {
			selectorLabels := labels.SelectorFromSet(labelMap)

			err = checkPodExistence(ctx, k8sClient, namespace, selectorLabels)
			if err != nil {
				errs = append(errs, err)
			}
		} else {
			logger.Info("Skipping pod existence check (no labels available)")
		}

		if kind == "CiliumNetworkPolicy" {
			err = validateServices(ctx, k8sClient, namespace, labelMap)
			if err != nil {
				errs = append(errs, err)
			}
		}

	}

	return errs
}

// checkPodExistence checks if the Pods matching the selector exist.
func checkPodExistence(ctx context.Context, k8sClient client.Client, namespace string, selector labels.Selector) error {
	var pods corev1.PodList
	logger := log.FromContext(ctx)

	listOpts := []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingLabelsSelector{Selector: selector},
	}

	if err := k8sClient.List(ctx, &pods, listOpts...); err != nil {
		logger.Error(err, "Failed to list pods", "namespace", namespace, "labels", selector)
		return fmt.Errorf("error listing pods: %v", err)
	}

	if len(pods.Items) == 0 {
		return fmt.Errorf("no matching pods found in namespace %s with labels %v", namespace, selector)
	}

	for _, pod := range pods.Items {
		logger.Info("Matching pod found", "podName", pod.Name, "namespace", namespace)
	}

	return nil
}

// validateServices checks if the Services matching the selector exist.
func validateServices(ctx context.Context, k8sClient client.Client, namespace string, matchLabels map[string]string) error {
	var services corev1.ServiceList
	if err := k8sClient.List(ctx, &services); err != nil {
		return errors.Errorf("error fetching services: %v", err)
	}
	for _, svc := range services.Items {
		if svc.Spec.Selector == nil {
			continue
		}
		match := true
		for k, v := range matchLabels {
			if svc.Spec.Selector[k] != v {
				match = false
				break
			}
		}
		if match {
			return nil
		}
	}
	return errors.Errorf("no services found matching the selector")
}

// validateNamespaces checks the existence of the namespace.
func validateNamespaces(ctx context.Context, k8sClient client.Client, namespace string) error {
	// Usa Get diretto invece della cache
	var ns corev1.Namespace
	err := k8sClient.Get(ctx, types.NamespacedName{Name: namespace}, &ns)
	if err != nil {
		// Fallback: ignora l'errore di timeout del namespace
		if strings.Contains(err.Error(), "Timeout") || strings.Contains(err.Error(), "sync") {
			return nil
		}
		return errors.Errorf("error fetching namespace '%s': %v", namespace, err)
	}
	return nil
}

// validateNamespaceStatus checks the status of the namespace to ensure it is active.
func validateNamespaceStatus(ctx context.Context, k8sClient client.Client, namespace string) error {
	var ns corev1.Namespace
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: namespace}, &ns); err != nil {
		return errors.Errorf("error fetching namespace '%s': %v", namespace, err)
	}

	if ns.Status.Phase != corev1.NamespaceActive {
		return errors.Errorf("namespace '%s' is not in an active phase", namespace)
	}

	return nil
}
