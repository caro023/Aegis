package policygenerator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/cclab-inu/KubeTeus/pkg/utils"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func PolicyGenerator(ctx context.Context, k8sClient client.Client, model string, prompts utils.Prompt) (utils.Policy, error) {
	var policy utils.Policy
	logger := log.FromContext(ctx)
	models := utils.SelectModel(model)
	if len(prompts.Network) > 0 {
		networkPolicies, testScript, err := generatePolicy(ctx, prompts.Network, "http://localhost:5000/generate", models.Network, prompts.PodDiscovery)
		if err == nil {
			policy.Network = networkPolicies
			policy.TestScript = testScript
		} else {
			logger.Info("Network policy generation failed")
		}
	}
	return policy, nil
}

func generatePolicy(ctx context.Context, prompts []string, url string, model string, podDiscovery []utils.PodDiscoveryInfo) ([]string, string, error) {
	logger := log.FromContext(ctx)
	var results []string
	var testScript string

	for _, prompt := range prompts {
		body, err := json.Marshal(map[string]interface{}{
			"model":         model,
			"prompt":        prompt,
			"pod_discovery": podDiscovery,
		})
		if err != nil {
			return nil, "", fmt.Errorf("failed to marshal request: %v", err)
		}

		resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
		if err != nil {
			return nil, "", fmt.Errorf("failed to call generate endpoint: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return nil, "", fmt.Errorf("non-200 response: %d - %s", resp.StatusCode, string(bodyBytes))
		}

		var result struct {
			Yaml string `json:"yaml"`
			Test string `json:"test"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, "", fmt.Errorf("failed to decode response JSON: %v", err)
		}
		logger.Info("Policy generation succeeded")

		if result.Yaml == "" {
			return nil, "", fmt.Errorf("empty yaml field in response")
		}

		results = append(results, result.Yaml)
		testScript = result.Test
		logger.Info("Policy generated", "Result", results)
	}

	return results, testScript, nil
}
