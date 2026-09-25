package tester

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// RunTestScript write the script and execute it
func RunTestScript(ctx context.Context, script string) (string, error) {
	logger := log.FromContext(ctx)

	tmpDir := os.TempDir()
	scriptPath := filepath.Join(tmpDir, "kubeteus_test.sh")

	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		return "", fmt.Errorf("failed to write test script: %w", err)
	}
	defer os.Remove(scriptPath)

	logger.Info("Running test script", "path", scriptPath)

	cmd := exec.CommandContext(ctx, "bash", scriptPath)
	out, err := cmd.CombinedOutput()
	output := string(out)

	logger.Info("Test script output:\n" + output)

	//Check if the tools are available
	if isToolUnavailable(output) {
		logger.Info("WARNING: connectivity tools not available in target containers — skipping tests, policy will be kept")
		return output, nil //nil -> no rollback
	}

	if strings.Contains(output, "FAIL") {
		return output, fmt.Errorf("one or more connectivity tests FAILED")
	}

	if err != nil {
		return output, fmt.Errorf("test script execution error: %w", err)
	}

	return output, nil
}

func isToolUnavailable(output string) bool {
	toolErrors := []string{
		"executable file not found in $PATH",
		"exec: \"curl\"",
		"exec: \"nc\"",
		"exec: \"sh\"",
		"exec: \"bash\"",
		"exec: \"wget\"",
		"no such file or directory",
		"OCI runtime exec failed",
	}
	for _, e := range toolErrors {
		if strings.Contains(output, e) {
			return true
		}
	}
	return false
}
