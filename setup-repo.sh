#!/bin/bash

# WAF + Reverse Proxy - Git Repository Setup Script
# This script initializes the git repository and pushes to GitHub

set -e

echo "🚀 Setting up WAF + Reverse Proxy Git Repository"
echo "================================================"

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed. Please install Git first."
    exit 1
fi

# Get repository URL from user
read -p "📝 Enter your GitHub repository URL (e.g., https://github.com/username/waf-reverse-proxy.git): " REPO_URL

if [ -z "$REPO_URL" ]; then
    echo "❌ Repository URL is required."
    exit 1
fi

# Initialize git repository if not already initialized
if [ ! -d ".git" ]; then
    echo "🔧 Initializing git repository..."
    git init
else
    echo "✅ Git repository already initialized"
fi

# Add all files
echo "📦 Adding files to git..."
git add .

# Check if there are any changes to commit
if git diff --staged --quiet; then
    echo "ℹ️  No changes to commit"
else
    # Commit files
    echo "💾 Committing files..."
    git commit -m "Initial commit: WAF + Reverse Proxy implementation

Features:
- Complete WAF engine with OWASP Top 10 protection
- Advanced reverse proxy with load balancing
- Rate limiting and bot protection
- Geo-blocking capabilities
- Comprehensive observability (metrics, logging)
- Health checks and circuit breakers
- Admin API for configuration management
- Docker deployment setup
- Prometheus monitoring integration

Built with Rust following SOLID principles for reliability, scalability, and availability."
fi

# Add remote origin
echo "🔗 Adding remote origin..."
if git remote | grep -q "origin"; then
    git remote set-url origin "$REPO_URL"
else
    git remote add origin "$REPO_URL"
fi

# Set main branch
git branch -M main

# Push to GitHub
echo "🚀 Pushing to GitHub..."
git push -u origin main

echo ""
echo "✅ SUCCESS! Repository has been pushed to GitHub"
echo "🌐 Repository URL: $REPO_URL"
echo ""
echo "📋 Next steps:"
echo "  1. Visit your repository on GitHub"
echo "  2. Add topics/tags for discoverability"
echo "  3. Set up GitHub Actions for CI/CD (optional)"
echo "  4. Configure branch protection rules (optional)"
echo ""
echo "🔧 To deploy locally:"
echo "  cargo build --release"
echo "  ./target/release/waf-reverse-proxy --config config.yaml"
echo ""
echo "🐳 To deploy with Docker:"
echo "  docker-compose up -d"
echo ""
echo "Happy coding! 🎉"
