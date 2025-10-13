# sentinel

## Build Instructions

### Prerequisites
- CMake ≥ 3.18  
- C++17 compiler
- libcurl development headers and library installed  
- gumbo-parser (HTML parsing)
- nlohmann/json (JSON handling)

On Debian/Ubuntu:
```bash
sudo apt install build-essential cmake libcurl4-openssl-dev libgumbo-dev nlohmann-json3-dev
```

### Build
```bash
cmake -S . -B build
cmake --build build
```

### Run
```bash
./build/sentinel --target <target_url> --out <output_dir> [--openapi file.json]
```
