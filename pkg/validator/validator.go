// validator.go
package validator

import (
	"context"
	"encoding/json"

	"fmt"
	"sigs.k8s.io/yaml"

	"github.com/cclab-inu/KubeTeus/pkg/utils"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Validator(ctx context.Context, k8sClient client.Client, logger logr.Logger, podInfo utils.NetInfo, entities []utils.Entity, policies interface{}) ([]error, error) {
	var validationErrors []error

	// Convert []string in []interface{} if necessary
	var policySlice []interface{}
	switch v := policies.(type) {
	case []string:
		for _, s := range v {
			policySlice = append(policySlice, s)
		}
	case []interface{}:
		policySlice = v
	default:
		return nil, fmt.Errorf("unsupported policies type: %T", policies)
	}

	for _, policy := range policySlice {
		// Convert policy to map[string]interface{}
		policyMap, err := toMap(policy)
		if err != nil {
			validationErrors = append(validationErrors, err)
			continue
		}
		if errs := CRDValidator(policyMap); len(errs) > 0 {
			validationErrors = append(validationErrors, errs...)
		}
	}
	if len(validationErrors) > 0 {
		return validationErrors, nil
	} else {
		logger.Info("[CRD Validator] Policy CRD syntax validated", "Result", "No problems")
	}

	resourceValidationErrors := ResourceValidator(ctx, k8sClient, logger, policies)
	if len(resourceValidationErrors) > 0 {
		validationErrors = append(validationErrors, resourceValidationErrors...)
	}
	logger.Info("[Resource Validator] Resource Validator done")

	propertyValidationErrors := PropertyValidator(ctx, k8sClient, policies)
	if len(propertyValidationErrors) > 0 {
		validationErrors = append(validationErrors, propertyValidationErrors...)
	}
	logger.Info("[Property Validator] Property Validator done")

	return validationErrors, nil
}

func toMap(policy interface{}) (map[string]interface{}, error) {
	// If it's a YAML string, convert it in JSON
	if yamlStr, ok := policy.(string); ok {
		jsonBytes, err := yaml.YAMLToJSON([]byte(yamlStr))
		if err != nil {
			return nil, fmt.Errorf("failed to convert YAML to JSON: %v", err)
		}
		var policyMap map[string]interface{}
		if err := json.Unmarshal(jsonBytes, &policyMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
		}
		return policyMap, nil
	}

	// Otherwise serialize and deserialize
	data, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	var policyMap map[string]interface{}
	if err := json.Unmarshal(data, &policyMap); err != nil {
		return nil, err
	}
	return policyMap, nil
}
