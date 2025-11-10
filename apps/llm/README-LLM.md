# Sentinel LLM Integration

Minimal Ollama client integration for Sentinel security scanner.

## Quick Start

### 1. Install Ollama

Download and install Ollama from https://ollama.ai

```bash
# macOS/Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Or download from https://ollama.ai/download
```

### 2. Pull a Model

Pull a model that's compatible with your use case:

```bash
ollama pull llama3.1
# or
ollama pull llama3.2
# or
ollama pull mistral
```

Verify the model is available:

```bash
ollama list
```

### 3. Start Ollama Server

```bash
ollama serve
```

The server runs on `http://127.0.0.1:11434` by default.

### 4. Set Environment Variable (Optional)

If your Ollama server is on a different host/port:

```bash
export OLLAMA_HOST=http://192.168.1.100:11434
```

### 5. Build

```bash
# Build everything
cmake -S . -B build
cmake --build build

# Or build just LLM components
make llm-build
```

The executable will be at: `build/apps/llm/sentinel_llm`

### 6. Run Demo

```bash
# Quick demo script
./tools/llm_demo.sh

# Or manually
./build/apps/llm/sentinel_llm --model llama3.1 --prompt "Generate a curl command"
```

### 7. Run Tests

```bash
# Run LLM tests
make llm-test

# Or run all tests
make test
```

## Usage

### Basic Usage

```bash
./build/apps/llm/sentinel_llm --model llama3:instruct --prompt "Hello, world!"
```

### With JSON Output

```bash
./build/apps/llm/sentinel_llm --model llama3:instruct --prompt "Generate a curl command" --json
```

### Environment Variables

Set `OLLAMA_HOST` to point to a different Ollama server:

```bash
export OLLAMA_HOST=http://192.168.1.100:11434
./build/apps/llm/sentinel_llm --model llama3:instruct --prompt "Test"
```

Default: `http://127.0.0.1:11434`

## Configuration

Edit `config/llm.yaml` to change default model, temperature, and timeout settings.

## API

### OllamaClient Class

Located in `src/llm/ollama_client.h`:

- `OllamaClient(host)` - Constructor (reads OLLAMA_HOST env var if host empty)
- `IsHealthy()` - Check if server is reachable
- `Generate(model, prompt, json_schema, timeout, stream)` - Generate text

### Helper Functions

- `llm::BuildPoEPrompt(finding_json)` - Build PoE prompt from finding
- `llm::BuildSafetyScorePrompt(input_snippet)` - Build safety score prompt
- `llm::RenderPoE(llm_result)` - Render PoE from LLM response

## Error Handling

The client throws `std::runtime_error` on:
- Network connection failures
- HTTP non-200 status codes
- JSON parse errors

All errors include descriptive messages.

## Limitations

- No streaming support (stream parameter exists but not fully implemented)
- JSON schema support depends on Ollama model capabilities
- Single request/response model (no conversation context)

---

## "Done Means Done" Checklist

### ✅ 1. Build

- [x] `cmake -S . -B build && cmake --build build` completes with no warnings promoted to errors for the new targets
- [x] All LLM targets (`sentinel_llm`, `test_ollama_client`, `test_poe_renderer`) build successfully
- [x] No compilation errors or warnings

### ✅ 2. Tests

- [x] `ctest -j2` runs and includes the new llm tests (`test_ollama_client`, `test_poe_renderer`)
- [x] All llm tests pass without a live Ollama server (using mock HTTP server)
- [x] Tests complete in under 2 seconds total
- [x] `make llm-test` runs successfully

### ✅ 3. CLI

- [x] `./build/apps/llm/sentinel_llm --model llama3.1 --prompt "hello"` prints a non-empty response or a graceful error if host unreachable
- [x] `./build/apps/llm/sentinel_llm --model llama3.1 --prompt '{"finding":"..."}' --json` prints a JSON string or a graceful error
- [x] `./tools/llm_demo.sh` runs successfully (builds, checks server, runs demo)

### ✅ 4. Non-invasiveness

- [x] Only the following files were created/modified:
  - `src/llm/ollama_client.h` (new)
  - `src/llm/prompt_templates.h` (new)
  - `src/llm/poe_renderer.h` (new)
  - `apps/llm/main.cpp` (new)
  - `apps/llm/CMakeLists.txt` (new)
  - `apps/llm/README-LLM.md` (new)
  - `tests/test_ollama_client.cpp` (new)
  - `tests/test_poe_renderer.cpp` (new)
  - `config/llm.yaml` (new)
  - `apps/demo_server/fixtures/poe_prompt.sample.json` (new)
  - `tools/llm_demo.sh` (new)
  - `CMakeLists.txt` (minimal edits: added llm library, test targets, subdirectory)
  - `src/sentinel_llm.cpp` (minimal adapter addition)
  - `.github/workflows/sentinel-scan.yml` (added test step)
  - `Makefile` (added llm-build, llm-test targets)
- [x] Root `README.md` remains untouched
- [x] `PHASE2_README.txt` remains untouched
- [x] Existing tests (`test_artifacts.cpp`, `test_budget.cpp`, `test_chain.cpp`) remain untouched

### ✅ 5. CI

- [x] `.github/workflows/sentinel-scan.yml` runs the new tests as part of CI
- [x] Test step added after build, before security scan
- [x] Uses `ctest -R "test_ollama_client|test_poe_renderer"` to run only LLM tests
- [x] Job time impact: +~30 seconds (tests run quickly with mock server)

### ✅ 6. Security/Policy

- [x] No OpenAI code or dependencies added
- [x] Only Ollama integration via HTTP using `third_party/httplib.h`
- [x] Network timeouts handled (5 second default, configurable)
- [x] Non-200 HTTP status codes handled gracefully (throws `std::runtime_error`)
- [x] No crashes on missing `OLLAMA_HOST` (defaults to `http://127.0.0.1:11434`)
- [x] All network errors caught and handled

### ✅ 7. Code Quality

- [x] All headers are guarded with `#pragma once`
- [x] No global state beyond reading `OLLAMA_HOST` environment variable
- [x] All new files are under 300 lines each:
  - `src/llm/ollama_client.h`: 190 lines
  - `src/llm/prompt_templates.h`: 58 lines
  - `src/llm/poe_renderer.h`: 58 lines
  - `apps/llm/main.cpp`: 102 lines
  - `tests/test_ollama_client.cpp`: 234 lines
  - `tests/test_poe_renderer.cpp`: 76 lines
- [x] C++20 standard used
- [x] No dynamic allocation gymnastics
- [x] Strict error handling with descriptive messages

---

**Status: ✅ All acceptance criteria met and verified locally. Ready for CI.**

