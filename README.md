# Aegis

**Aegis** is a Kubernetes controller that turns **natural-language network intents** into enforced **Cilium/Calico `NetworkPolicy`** resources. Instead of hand-writing YAML network policies, a user describes what they want in natural-text (e.g. *"the api-backend should be able to reach the cache service"*), and Aegis translates that intent into a concrete policy, validates it, applies it to the cluster, and tests that the resulting traffic behavior matches the intent.

## How it works

The system is organized as a pipeline of packages under `pkg/`, orchestrated by the controller in `internal/controller/`:

The controller exposes an HTTP endpoint (`POST /intent` on `localhost:9090`) that accepts a plain-text intent and runs it through the pipeline above. 

The CLI UI (`internal/ui/ui.go`) is a client that reads intents from the terminal and posts them to this endpoint.

## Prerequisites

- **Go** 1.23+ (the module targets Go 1.25; a local Go 1.23.6 tarball is vendored in the repo root for convenience)
- **Docker**, running — the controller needs to connect to it 
- A **Kubernetes cluster**. The repo includes [`kind`](https://kind.sigs.k8s.io/) configs for a CNI-aware cluster:
  - `kind-cilium.yaml` for Cilium
  - `kind-calico.yaml` for Calico
- API keys for the LLM backends used by the policy generator:
  - `GROQ_API_KEY`
  - `OLLAMA_API_KEY`
- `make`, `kubectl`

## Setup

1. Clone the repository.
2. Export the required API keys:
   ```bash
   export GROQ_API_KEY="<your-groq-api-key>"
   export OLLAMA_API_KEY="<your-ollama-api-key>"
   ```
3. Make sure Docker is running.

## Running

Start the controller (server) in one terminal:

```bash
make run
```

By default it operates in the `default` namespace. To target a specific namespace instead:

```bash
make run TEST_NAMESPACE="test-pods"
```

In a second terminal, start the interactive CLI to submit intents:

```bash
make ui
```

Then type a natural-language intent at the prompt, e.g.:

```
Enter your intent (or type 'q' to quit): I want the api-backend to be able to reach the cache service.
```

Type `q` to exit the UI.

### Batch-testing multiple intents

The `test_script/` folder contains ready-made batches of sample intents at different levels of specificity:

- `intenti_generici.sh` – generic intents
- `intenti_intermedi.sh` – intermediate intents
- `intenti_specifici.sh` – specific intents

With the controller running (`make run`), execute one of them to send many intents in sequence against the `POST /intent` endpoint:

```bash
cd test_script
./intenti_generici.sh
```

Results of these runs are logged under `results/` (`passed.txt`, `failed.txt`, `skipped.txt`).

## Acknowledgements

This project originated from [KubeTeus](https://github.com/cclab-inu/KubeTeus), developed by the Cybersecurity Convergence Lab (CCLAB) at Incheon National University.

The original KubeTeus framework provided the starting point and inspiration for the work presented in this repository.

This repository contains a substantially modified and extended implementation developed as part of an academic thesis. The original codebase has undergone changes, including modifications to its architecture and core logic, removal of certain components, and the development of new functionalities and features.


**Original project:** [cclab-inu/KubeTeus](https://github.com/cclab-inu/KubeTeus)

**Original research:** [KubeTeus – IEEE INFOCOM 2025](https://cclab.info/papers/2025_kim_infocom.pdf)

## License
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

