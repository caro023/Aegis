package enforcer

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/yaml"
)

func Enforcer(ctx context.Context, k8sClient client.Client, policies interface{}) error {
	// Supporta sia []string che []interface{}
	var policySlice []interface{}
	switch v := policies.(type) {
	case []string:
		for _, s := range v {
			policySlice = append(policySlice, s)
		}
	case []interface{}:
		policySlice = v
	default:
		return fmt.Errorf("failed to assert policies as a slice of interfaces")
	}

	for _, policyInterface := range policySlice {
		unstructuredPolicy, err := convertToUnstructured(policyInterface)
		if err != nil {
			return fmt.Errorf("failed to convert policy to unstructured: %v", err)
		}
		if err := applyPolicy(ctx, k8sClient, unstructuredPolicy); err != nil {
			return err
		}
	}
	return nil
}

func convertToUnstructured(obj interface{}) (*unstructured.Unstructured, error) {
	// If it's a YAML string parse it directly
	if yamlStr, ok := obj.(string); ok {
		var objMap map[string]interface{}
		if err := yaml.Unmarshal([]byte(yamlStr), &objMap); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %v", err)
		}
		return &unstructured.Unstructured{Object: objMap}, nil
	}
	// try standard conversion otherwise
	if m, ok := obj.(map[string]interface{}); ok {
		return &unstructured.Unstructured{Object: m}, nil
	}
	return nil, fmt.Errorf("unsupported policy type: %T", obj)
}

func applyPolicy(ctx context.Context, k8sClient client.Client, policy *unstructured.Unstructured) error {
	if err := k8sClient.Create(ctx, policy); err != nil {
		if errors.IsAlreadyExists(err) {
			//get the existing policy
			existing := &unstructured.Unstructured{}
			existing.SetGroupVersionKind(policy.GroupVersionKind())

			key := client.ObjectKey{
				Name:      policy.GetName(),
				Namespace: policy.GetNamespace(),
			}

			if err := k8sClient.Get(ctx, key, existing); err != nil {
				return fmt.Errorf("failed to get existing policy: %v", err)
			}

			// copy the resourceVersion
			policy.SetResourceVersion(existing.GetResourceVersion())

			// Update
			if err := k8sClient.Update(ctx, policy); err != nil {
				return fmt.Errorf("failed to update existing policy: %v", err)
			}
		} else {
			return fmt.Errorf("failed to create policy: %v", err)
		}
	}
	return nil
}

func Rollback(ctx context.Context, k8sClient client.Client, policies []string) error {
	logger := log.FromContext(ctx)

	for _, raw := range policies {
		obj := &unstructured.Unstructured{}
		if err := yaml.Unmarshal([]byte(raw), &obj.Object); err != nil {
			logger.Error(err, "failed to unmarshal policy for rollback")
			continue
		}

		if err := k8sClient.Delete(ctx, obj); err != nil {
			if !errors.IsNotFound(err) {
				return fmt.Errorf("rollback failed for %s: %w", obj.GetName(), err)
			}
		}
		logger.Info("Rolled back policy", "name", obj.GetName())
	}
	return nil
}
