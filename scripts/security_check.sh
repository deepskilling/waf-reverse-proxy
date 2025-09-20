#!/bin/bash
# Security Check Script for WAF + Reverse Proxy
# Runs comprehensive security analysis on both Rust and Python implementations

echo "🔒 WAF + Reverse Proxy Security Analysis"
echo "========================================"

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if required tools are installed
check_tool() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${YELLOW}Warning: $1 not found, skipping $2 checks${NC}"
        return 1
    fi
    return 0
}

echo "🔍 Checking security analysis tools..."

# Rust security checks
echo -e "\n${BLUE}=== Rust Security Analysis ===${NC}"
if check_tool cargo "Rust dependency"; then
    echo "📦 Checking Rust dependencies for vulnerabilities..."
    if cargo audit --version &> /dev/null; then
        cargo audit || echo -e "${RED}❌ Rust vulnerabilities found!${NC}"
    else
        echo -e "${YELLOW}Installing cargo-audit...${NC}"
        cargo install cargo-audit
        cargo audit || echo -e "${RED}❌ Rust vulnerabilities found!${NC}"
    fi
    
    echo "🔍 Running Rust linting checks..."
    cargo clippy -- -W clippy::all 2>/dev/null || echo -e "${YELLOW}⚠️  Clippy warnings found${NC}"
else
    echo -e "${YELLOW}Skipping Rust security checks${NC}"
fi

# Python security checks
echo -e "\n${BLUE}=== Python Security Analysis ===${NC}"
if check_tool python3 "Python"; then
    echo "📦 Checking Python dependencies for vulnerabilities..."
    
    # Install security tools if not present
    if ! command -v safety &> /dev/null; then
        echo "Installing safety..."
        pip install safety
    fi
    
    if ! command -v bandit &> /dev/null; then
        echo "Installing bandit..."
        pip install bandit
    fi
    
    # Run Python security checks
    cd python_implementation 2>/dev/null || echo "Note: python_implementation directory not found"
    
    if [ -f requirements.txt ]; then
        echo "🔍 Scanning Python dependencies..."
        safety scan -r requirements.txt || echo -e "${RED}❌ Python vulnerabilities found!${NC}"
    fi
    
    echo "🔍 Running static analysis with bandit..."
    bandit -r pywaf/ -f json -o ../security_bandit_report.json 2>/dev/null || \
        echo -e "${YELLOW}⚠️  Bandit analysis completed with findings${NC}"
    
    cd ..
else
    echo -e "${YELLOW}Skipping Python security checks${NC}"
fi

# Configuration security checks
echo -e "\n${BLUE}=== Configuration Security Analysis ===${NC}"
echo "🔍 Checking for security misconfigurations..."

# Check for default passwords
echo "🔐 Checking for default/weak credentials..."
if grep -r "password.*admin\|admin.*password\|secret.*change" config/ python_implementation/config/ 2>/dev/null; then
    echo -e "${RED}❌ Default credentials found in configuration files!${NC}"
fi

# Check for debug mode enabled
echo "🐛 Checking for debug mode..."
if grep -r "debug.*true\|debug:\s*true" config/ python_implementation/config/ 2>/dev/null; then
    echo -e "${YELLOW}⚠️  Debug mode enabled in configuration${NC}"
fi

# Check for insecure bindings
echo "🌐 Checking for insecure network bindings..."
if grep -r "0\.0\.0\.0" config/ python_implementation/config/ 2>/dev/null; then
    echo -e "${YELLOW}⚠️  Binding to 0.0.0.0 - ensure proper firewall rules${NC}"
fi

# Check for weak SSL/TLS settings
echo "🔒 Checking SSL/TLS configuration..."
if grep -r "TLSv1\.0\|TLSv1\.1\|SSLv" config/ python_implementation/config/ 2>/dev/null; then
    echo -e "${RED}❌ Weak SSL/TLS protocols detected!${NC}"
fi

# File permissions check
echo -e "\n${BLUE}=== File Permissions Analysis ===${NC}"
echo "🔍 Checking file permissions..."

# Check for overly permissive files
find . -type f -name "*.yaml" -o -name "*.yml" -o -name "*.json" -o -name "*.toml" | while read file; do
    perms=$(stat -c "%a" "$file" 2>/dev/null || stat -f "%A" "$file" 2>/dev/null)
    if [ "$perms" = "777" ] || [ "$perms" = "666" ]; then
        echo -e "${YELLOW}⚠️  Overly permissive file: $file ($perms)${NC}"
    fi
done

# Check for potential secret files
echo "🔐 Checking for potential secret files..."
find . -name "*.pem" -o -name "*.key" -o -name "*.crt" -o -name ".env" | while read file; do
    if [ -f "$file" ]; then
        echo -e "${YELLOW}⚠️  Secret file found: $file${NC}"
    fi
done

# Summary
echo -e "\n${BLUE}=== Security Analysis Summary ===${NC}"
echo "📊 Analysis completed. Review findings above."
echo "📄 See docs/SECURITY_ANALYSIS.md for detailed security report."
echo ""
echo -e "${GREEN}✅ Completed security analysis${NC}"
echo -e "For detailed remediation steps, see: ${BLUE}docs/SECURITY_ANALYSIS.md${NC}"
