package enforcer

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/yaml"
)

func Enforcer(ctx context.Context, k8sClient client.Client, policies interface{}) error {
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
		// ← ora gestisce multi-documento
		unstructuredPolicies, err := convertToUnstructuredMulti(policyInterface)
		if err != nil {
			return fmt.Errorf("failed to convert policy to unstructured: %v", err)
		}
		for _, up := range unstructuredPolicies {
			if err := applyPolicy(ctx, k8sClient, up); err != nil {
				return err
			}
		}
	}
	return nil
}

// convertToUnstructuredMulti gestisce sia singolo YAML che multi-documento (---)
func convertToUnstructuredMulti(obj interface{}) ([]*unstructured.Unstructured, error) {
	yamlStr, ok := obj.(string)
	if !ok {
		// fallback: map singola
		if m, ok := obj.(map[string]interface{}); ok {
			return []*unstructured.Unstructured{
				{Object: m},
			}, nil
		}
		return nil, fmt.Errorf("unsupported policy type: %T", obj)
	}

	var results []*unstructured.Unstructured
	for _, doc := range splitYAMLDocuments(yamlStr) {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}
		var objMap map[string]interface{}
		if err := yaml.Unmarshal([]byte(doc), &objMap); err != nil {
			return nil, fmt.Errorf("failed to parse YAML document: %v", err)
		}
		if len(objMap) == 0 {
			continue
		}
		results = append(results, &unstructured.Unstructured{Object: objMap})
	}
	return results, nil
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
		documents := splitYAMLDocuments(raw)

		for _, doc := range documents {
			doc = strings.TrimSpace(doc)
			if doc == "" {
				continue
			}

			obj := &unstructured.Unstructured{}
			if err := yaml.Unmarshal([]byte(doc), &obj.Object); err != nil {
				logger.Error(err, "failed to unmarshal policy for rollback", "doc", doc)
				continue
			}

			if obj.GetName() == "" {
				logger.Info("Skipping empty object during rollback")
				continue
			}

			if err := k8sClient.Delete(ctx, obj); err != nil {
				if !errors.IsNotFound(err) {
					return fmt.Errorf("rollback failed for %s: %w", obj.GetName(), err)
				}
				logger.Info("Policy already removed", "name", obj.GetName())
			} else {
				logger.Info("Rolled back policy", "name", obj.GetName())
			}
		}
	}
	return nil
}

func splitYAMLDocuments(raw string) []string {
	// Splitta su "---" che separa documenti YAML multipli
	parts := strings.Split(raw, "\n---")
	var docs []string
	for _, p := range parts {
		p = strings.TrimSpace(strings.TrimPrefix(p, "---"))
		if p != "" {
			docs = append(docs, p)
		}
	}
	return docs
}
