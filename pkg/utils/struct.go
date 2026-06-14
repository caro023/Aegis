package utils

type Policy struct {
	Network    []string
	TestScript string
}

type Models struct {
	Network string
}

type Configuration struct {
	User struct {
		Home string `yaml:"home"`
	} `yaml:"user"`
}

type Prompt struct {
	Network      []string
	PodDiscovery []PodDiscoveryInfo
}

type Entity struct {
	Text string `json:"text"`
	Type string `json:"type"`
}

type SamplePodInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"`
}

type PodCommunication struct {
	SrcPodInfo NetInfo
	DstPodInfo NetInfo
	Related    bool
}

type NetInfo struct {
	Name           string            `json:"name"`
	Namespace      string            `json:"namespace"`
	Labels         map[string]string `json:"labels"`
	ContainerPorts string            `json:"containerPorts"`
	Protocol       string            `json:"protocol"`
	ServiceName    string            `json:"serviceName"`
	RelatedEnv     []Service         `json:"relatedEnv"`
}

type Service struct {
	Name string
	Port string
}

type PodTraffic struct {
	SrcPod    string
	DstPod    string
	Direction string
	Protocol  string
	Port      int
	Status    string
}

type YAMLInfo struct {
	Name      string            `yaml:"name"`
	Namespace string            `yaml:"namespace"`
	Labels    map[string]string `yaml:"labels"`
}

type IntentQueue struct {
	Ch chan string
}

func NewIntentQueue(size int) *IntentQueue {
	return &IntentQueue{Ch: make(chan string, size)}
}

func (q *IntentQueue) Push(intent string) bool {
	select {
	case q.Ch <- intent:
		return true
	default:
		return false
	}
}

func (q *IntentQueue) Pop() (string, bool) {
	select {
	case intent := <-q.Ch:
		return intent, true
	default:
		return "", false
	}
}

type PodDiscoveryInfo struct {
	Name           string            `json:"name"`
	Namespace      string            `json:"namespace"`
	Ports          []PortInfo        `json:"ports"`
	Labels         map[string]string `json:"labels"`
	AvailableTools []string          `json:"availableTools"`
}

type PortInfo struct {
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"`
}
