package policygenerator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/cclab-inu/KubeTeus/pkg/utils"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func PolicyGenerator(ctx context.Context, k8sClient client.Client, model string, prompts utils.Prompt) (utils.Policy, error) {
	var policy utils.Policy
	logger := log.FromContext(ctx)
	models := utils.SelectModel(model)
	if len(prompts.Network) > 0 {
		networkPolicies, err := generatePolicy(ctx, prompts.Network, "http://localhost:5000/generate", models.Network)
		if err == nil {
			policy.Network = networkPolicies
		} else {
			logger.Error(err, "Network policy generation failed")
		}
	}
	return policy, nil
}

func generatePolicy(ctx context.Context, prompts []string, url string, model string) ([]string, error) {
	logger := log.FromContext(ctx)
	var results []string

	for _, prompt := range prompts {
		// Serializza correttamente il JSON con encoding/json per gestire newline e caratteri speciali
		body, err := json.Marshal(map[string]string{
			"model":  model,
			"prompt": prompt,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %v", err)
		}

		resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
		if err != nil {
			return nil, fmt.Errorf("failed to call generate endpoint: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("non-200 response: %d - %s", resp.StatusCode, string(bodyBytes))
		}

		outputBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %v", err)
		}
		output := string(outputBytes)
		logger.Info("Policy generation succeeded", "Output", output)

		re := regexp.MustCompile(`(?s)apiVersion:.*`)
		match := re.FindStringSubmatch(output)
		if len(match) > 0 {
			results = append(results, match[0])
		} else {
			return nil, fmt.Errorf("desired output not found in script response")
		}
	}

	logger.Info("Policy generated", "Result", results)
	return results, nil
}
