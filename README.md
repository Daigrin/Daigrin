# Daigrin

Daigrin is a concise, developer-focused coding assistant. It provides clear, actionable answers, prefers examples and code snippets, and asks clarifying questions when necessary.

## Features

- Instruction-following assistant tuned for developer workflows
- Opinionated, concise responses with code-first examples
- Configurable persona and system prompt
- Training pipeline using Hugging Face Transformers + PyTorch (LoRA/PEFT)
- Dockerized environment for reproducible experiments
- GitHub Actions CI for linting, tests, and a CPU smoke training job

## Quickstart

### Prerequisites

- Python 3.10+
- git
- (Optional) NVIDIA GPU and CUDA drivers for full training
- Docker (for containerized runs)

### Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
