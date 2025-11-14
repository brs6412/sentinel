#!/bin/bash
# install_dependencies.sh - Install all dependencies required to build and run Sentinel
#
# This script detects your operating system and installs the required packages.
# It supports Debian/Ubuntu, macOS (Homebrew), Fedora/RHEL, and Arch Linux.
#
# Usage:
#   ./tools/install_dependencies.sh
#
# Note: Requires sudo/root privileges for package installation

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

error() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

info() {
    echo -e "${GREEN}$1${NC}"
}

warn() {
    echo -e "${YELLOW}Warning: $1${NC}"
}

# Detect operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            echo "debian"
        elif command -v dnf >/dev/null 2>&1; then
            echo "fedora"
        elif command -v yum >/dev/null 2>&1; then
            echo "rhel"
        elif command -v pacman >/dev/null 2>&1; then
            echo "arch"
        else
            echo "unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install dependencies for Debian/Ubuntu
install_debian() {
    info "Detected Debian/Ubuntu system"
    
    if ! command_exists sudo; then
        error "sudo is required but not found. Please install sudo or run as root."
    fi
    
    info "Updating package list..."
    sudo apt-get update
    
    info "Installing build dependencies..."
    sudo apt-get install -y \
        build-essential \
        cmake \
        libcurl4-openssl-dev \
        libgumbo-dev \
        nlohmann-json3-dev \
        libssl-dev \
        jq \
        curl \
        ripgrep \
        python3 \
        python3-pip \
        git
    
    info "Debian/Ubuntu dependencies installed successfully!"
}

# Install dependencies for Fedora
install_fedora() {
    info "Detected Fedora system"
    
    if ! command_exists sudo; then
        error "sudo is required but not found. Please install sudo or run as root."
    fi
    
    info "Installing build dependencies..."
    sudo dnf install -y \
        gcc \
        gcc-c++ \
        cmake \
        libcurl-devel \
        gumbo-parser-devel \
        nlohmann_json-devel \
        openssl-devel \
        jq \
        curl \
        ripgrep \
        python3 \
        python3-pip \
        git
    
    info "Fedora dependencies installed successfully!"
}

# Install dependencies for RHEL/CentOS
install_rhel() {
    info "Detected RHEL/CentOS system"
    
    if ! command_exists sudo; then
        error "sudo is required but not found. Please install sudo or run as root."
    fi
    
    info "Installing EPEL repository (required for some packages)..."
    sudo yum install -y epel-release || true
    
    info "Installing build dependencies..."
    sudo yum install -y \
        gcc \
        gcc-c++ \
        cmake \
        libcurl-devel \
        gumbo-parser-devel \
        nlohmann_json-devel \
        openssl-devel \
        jq \
        curl \
        ripgrep \
        python3 \
        python3-pip \
        git
    
    info "RHEL/CentOS dependencies installed successfully!"
}

# Install dependencies for Arch Linux
install_arch() {
    info "Detected Arch Linux system"
    
    if ! command_exists sudo; then
        error "sudo is required but not found. Please install sudo or run as root."
    fi
    
    info "Installing build dependencies..."
    sudo pacman -S --noconfirm \
        base-devel \
        cmake \
        curl \
        gumbo-parser \
        nlohmann-json \
        openssl \
        jq \
        ripgrep \
        python \
        python-pip \
        git
    
    info "Arch Linux dependencies installed successfully!"
}

# Install dependencies for macOS
install_macos() {
    info "Detected macOS system"
    
    if ! command_exists brew; then
        error "Homebrew is required but not found. Please install Homebrew first: https://brew.sh"
    fi
    
    info "Installing build dependencies via Homebrew..."
    brew install \
        cmake \
        gumbo-parser \
        nlohmann-json \
        openssl \
        jq \
        curl \
        ripgrep \
        python3 \
        git
    
    info "macOS dependencies installed successfully!"
}

# Check for optional dependencies
check_optional() {
    echo ""
    info "Checking optional dependencies..."
    
    if ! command_exists ollama; then
        warn "Ollama is not installed. LLM features will not work."
        warn "To install Ollama, visit: https://ollama.ai"
        warn "After installation, start the server with: ollama serve"
    else
        info "Ollama is installed ✓"
        if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
            info "Ollama server is running ✓"
        else
            warn "Ollama is installed but not running. Start it with: ollama serve"
        fi
    fi
    
    if ! command_exists python3; then
        warn "Python 3 is not installed. Some tools may not work."
    else
        info "Python 3 is installed ✓"
    fi
}

# Verify installed dependencies
verify_dependencies() {
    echo ""
    info "Verifying installed dependencies..."
    
    local missing=()
    
    # Required build tools
    for cmd in cmake g++ gcc; do
        if ! command_exists "$cmd"; then
            missing+=("$cmd")
        fi
    done
    
    # Required libraries (check via pkg-config or headers)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS: check if libraries are available
        if ! brew list nlohmann-json >/dev/null 2>&1; then
            missing+=("nlohmann-json")
        fi
    else
        # Linux: try pkg-config
        if ! pkg-config --exists nlohmann_json 2>/dev/null && ! pkg-config --exists nlohmann_json3 2>/dev/null; then
            # Check if header exists
            if [[ ! -f /usr/include/nlohmann/json.hpp ]] && [[ ! -f /usr/local/include/nlohmann/json.hpp ]]; then
                missing+=("nlohmann-json")
            fi
        fi
    fi
    
    # Required runtime tools
    for cmd in jq curl rg python3; do
        if ! command_exists "$cmd"; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -eq 0 ]]; then
        info "All required dependencies are installed ✓"
        return 0
    else
        error "Missing dependencies: ${missing[*]}"
        return 1
    fi
}

# Main installation flow
main() {
    echo "=========================================="
    echo "Sentinel Dependency Installation Script"
    echo "=========================================="
    echo ""
    
    OS=$(detect_os)
    
    case "$OS" in
        debian)
            install_debian
            ;;
        fedora)
            install_fedora
            ;;
        rhel)
            install_rhel
            ;;
        arch)
            install_arch
            ;;
        macos)
            install_macos
            ;;
        unknown)
            error "Unsupported operating system. Please install dependencies manually."
            ;;
    esac
    
    check_optional
    verify_dependencies
    
    echo ""
    info "=========================================="
    info "Installation complete!"
    info "=========================================="
    echo ""
    info "Next steps:"
    echo "  1. Build Sentinel:"
    echo "     cmake -S . -B build -DCMAKE_BUILD_TYPE=Release"
    echo "     cmake --build build -j"
    echo ""
    echo "  2. Run tests:"
    echo "     ./tools/full_tests.sh"
    echo ""
    echo "  3. Run demo:"
    echo "     ./tools/full_demo.sh"
    echo ""
}

# Run main function
main "$@"

