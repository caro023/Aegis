package utils

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
)

func SelectModel(baseModel string) Models {
	if baseModel == "default" {
		return Models{
			Network: "cclabadmin/deepseek_base_network", // "cclabadmin/codegemma-7b-it-network",
		}
	}
	return Models{
		Network: baseModel,
	}
}

func LoadPodResources(resourceDir string) ([]v1.Pod, error) {
	var pods []v1.Pod

	files, err := os.ReadDir(resourceDir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".yaml" {
			content, err := os.ReadFile(filepath.Join(resourceDir, file.Name()))
			if err != nil {
				return nil, err
			}

			var pod v1.Pod
			err = yaml.Unmarshal(content, &pod)
			if err != nil {
				return nil, err
			}
			pods = append(pods, pod)
		}
	}
	return pods, nil
}

// readConfig reads and parses the YAML configuration file.
func ReadConfig(path string) (*Configuration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Configuration
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// logFailureWithTimestamp logs failure messages with a timestamp
func logFailureWithTimestamp(message string) {
	fmt.Printf("%s: %s", time.Now().Format(time.RFC3339), message)
}

// logSuccessWithTimestamp logs success messages with a timestamp
func logSuccessWithTimestamp(message string) {
	fmt.Printf("%s: %s", time.Now().Format(time.RFC3339), message)
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
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   command,
			Stdout:    true,
			Stderr:    false,
			TTY:       false,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &buf})
	return buf.String(), err
}
