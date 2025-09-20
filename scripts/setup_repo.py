#!/usr/bin/env python3
"""
WAF + Reverse Proxy - Git Repository Setup Script
=================================================

This script automates the process of setting up a Git repository 
and pushing the WAF + Reverse Proxy code to GitHub.

Usage:
    python setup_repo.py
    
Requirements:
    - Python 3.6+
    - Git installed and configured
    - GitHub repository created
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
from urllib.parse import urlparse
import requests
import json

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def load_env_file(env_path='.env'):
    """Load environment variables from .env file"""
    if not os.path.exists(env_path):
        return {}
    
    env_vars = {}
    try:
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    # Remove quotes if present
                    value = value.strip('"').strip("'")
                    env_vars[key.strip()] = value
                    # Also set in os.environ for subprocess access
                    os.environ[key.strip()] = value
    except Exception as e:
        print(f"{Colors.WARNING}⚠️  Warning: Could not load .env file: {e}{Colors.ENDC}")
    
    return env_vars

class GitSetup:
    """Handles Git repository setup and GitHub pushing"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.repo_url = None
        # Load environment variables
        self.env_vars = load_env_file()
        self.github_token = self.env_vars.get('GITHUB_TOKEN')
        self.github_username = self.env_vars.get('GITHUB_USERNAME')
        self.repo_name = self.env_vars.get('REPO_NAME', 'waf-reverse-proxy')
        self.repo_description = self.env_vars.get('REPO_DESCRIPTION', 'Enterprise WAF + Reverse Proxy')
        
    def print_header(self):
        """Print welcome header"""
        print(f"{Colors.HEADER}{Colors.BOLD}")
        print("🚀 WAF + Reverse Proxy - Git Repository Setup")
        print("=" * 50)
        print(f"{Colors.ENDC}")
        
    def check_prerequisites(self):
        """Check if required tools are installed"""
        print(f"{Colors.OKCYAN}🔍 Checking prerequisites...{Colors.ENDC}")
        
        # Check Git
        if not shutil.which("git"):
            print(f"{Colors.FAIL}❌ Git is not installed. Please install Git first.{Colors.ENDC}")
            print("   Download from: https://git-scm.com/downloads")
            return False
            
        # Check Git configuration
        try:
            subprocess.run(["git", "config", "user.name"], 
                         capture_output=True, check=True, text=True)
            subprocess.run(["git", "config", "user.email"], 
                         capture_output=True, check=True, text=True)
        except subprocess.CalledProcessError:
            print(f"{Colors.WARNING}⚠️  Git is not configured. Please run:{Colors.ENDC}")
            print("   git config --global user.name 'Your Name'")
            print("   git config --global user.email 'your.email@example.com'")
            return False
            
        print(f"{Colors.OKGREEN}✅ Prerequisites check passed{Colors.ENDC}")
        return True
        
    def get_repository_url(self):
        """Get GitHub repository URL from user"""
        print(f"\n{Colors.OKCYAN}📝 Repository Configuration{Colors.ENDC}")
        print("Please provide your GitHub repository URL.")
        print("Example formats:")
        print("  • https://github.com/username/waf-reverse-proxy.git")
        print("  • git@github.com:username/waf-reverse-proxy.git")
        print()
        
        while True:
            url = input("Repository URL: ").strip()
            if not url:
                print(f"{Colors.FAIL}❌ Repository URL is required.{Colors.ENDC}")
                continue
                
            if self.validate_repo_url(url):
                self.repo_url = url
                break
            else:
                print(f"{Colors.FAIL}❌ Invalid repository URL format.{Colors.ENDC}")
                
    def validate_repo_url(self, url):
        """Validate repository URL format"""
        if url.startswith("git@github.com:"):
            return url.endswith(".git") and "/" in url
        elif url.startswith("https://github.com/"):
            parsed = urlparse(url)
            return parsed.netloc == "github.com" and len(parsed.path.strip("/").split("/")) >= 2
        return False
    
    def create_github_repo(self):
        """Create GitHub repository using API if token is available"""
        if not self.github_token:
            print(f"{Colors.WARNING}⚠️  No GitHub token found in .env file{Colors.ENDC}")
            print("Repository creation via API skipped - you'll need to create it manually")
            return False
            
        print(f"\n{Colors.OKCYAN}🌐 Creating GitHub Repository via API{Colors.ENDC}")
        
        headers = {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json'
        }
        
        repo_data = {
            'name': self.repo_name,
            'description': self.repo_description,
            'private': False,
            'auto_init': False,
            'gitignore_template': None,
            'license_template': None
        }
        
        try:
            response = requests.post(
                'https://api.github.com/user/repos',
                headers=headers,
                json=repo_data,
                timeout=30
            )
            
            if response.status_code == 201:
                repo_info = response.json()
                self.repo_url = repo_info['clone_url']
                print(f"{Colors.OKGREEN}✅ Repository created successfully!{Colors.ENDC}")
                print(f"   📍 URL: {repo_info['html_url']}")
                print(f"   📋 Clone URL: {self.repo_url}")
                return True
            elif response.status_code == 422:
                error_data = response.json()
                if any('already exists' in str(error).lower() for error in error_data.get('errors', [])):
                    print(f"{Colors.WARNING}⚠️  Repository already exists{Colors.ENDC}")
                    # Try to get the existing repository info
                    self.repo_url = f"https://github.com/{self.github_username}/{self.repo_name}.git"
                    return True
                else:
                    print(f"{Colors.FAIL}❌ Repository creation failed: {error_data.get('message', 'Unknown error')}{Colors.ENDC}")
                    return False
            else:
                print(f"{Colors.FAIL}❌ GitHub API error ({response.status_code}): {response.text}{Colors.ENDC}")
                return False
                
        except requests.RequestException as e:
            print(f"{Colors.FAIL}❌ Network error creating repository: {e}{Colors.ENDC}")
            return False
        
    def initialize_git_repo(self):
        """Initialize Git repository if not exists"""
        print(f"\n{Colors.OKCYAN}🔧 Git Repository Setup{Colors.ENDC}")
        
        os.chdir(self.project_root)
        
        if not (self.project_root / ".git").exists():
            print("Initializing git repository...")
            result = subprocess.run(["git", "init"], capture_output=True, text=True)
            if result.returncode != 0:
                print(f"{Colors.FAIL}❌ Failed to initialize git repository: {result.stderr}{Colors.ENDC}")
                return False
            print(f"{Colors.OKGREEN}✅ Git repository initialized{Colors.ENDC}")
        else:
            print(f"{Colors.OKGREEN}✅ Git repository already exists{Colors.ENDC}")
            
        return True
        
    def add_and_commit_files(self):
        """Add all files and create initial commit"""
        print(f"\n{Colors.OKCYAN}📦 Adding and committing files...{Colors.ENDC}")
        
        # Add all files
        result = subprocess.run(["git", "add", "."], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"{Colors.FAIL}❌ Failed to add files: {result.stderr}{Colors.ENDC}")
            return False
            
        # Check if there are changes to commit
        result = subprocess.run(["git", "diff", "--staged", "--quiet"], capture_output=True)
        if result.returncode == 0:
            print(f"{Colors.WARNING}ℹ️  No changes to commit{Colors.ENDC}")
            return True
            
        # Create commit
        commit_message = """Initial commit: WAF + Reverse Proxy implementation

🚀 Features implemented:
- Complete WAF engine with OWASP Top 10 protection
- Advanced reverse proxy with load balancing
- Rate limiting and bot protection
- Geo-blocking capabilities
- Comprehensive observability (metrics, logging)
- Health checks and circuit breakers
- Admin API for configuration management
- Docker deployment setup
- Prometheus monitoring integration

🏗️ Architecture:
- Built with Rust following SOLID principles
- Designed for reliability, scalability, and availability
- Modular design with clean separation of concerns
- Comprehensive error handling and recovery

🔧 Deployment:
- Docker and Docker Compose ready
- Kubernetes compatible
- Prometheus metrics integration
- Grafana dashboards included

📊 Performance:
- Async/await architecture for high concurrency
- Efficient memory management
- Connection pooling and caching
- Circuit breakers for resilience"""

        result = subprocess.run(["git", "commit", "-m", commit_message], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print(f"{Colors.FAIL}❌ Failed to commit: {result.stderr}{Colors.ENDC}")
            return False
            
        print(f"{Colors.OKGREEN}✅ Files committed successfully{Colors.ENDC}")
        return True
        
    def setup_remote_and_push(self):
        """Setup remote origin and push to GitHub"""
        print(f"\n{Colors.OKCYAN}🔗 Setting up remote origin and pushing...{Colors.ENDC}")
        
        # Check if remote origin exists
        result = subprocess.run(["git", "remote"], capture_output=True, text=True)
        if "origin" in result.stdout:
            print("Updating existing remote origin...")
            result = subprocess.run(["git", "remote", "set-url", "origin", self.repo_url], 
                                  capture_output=True, text=True)
        else:
            print("Adding remote origin...")
            result = subprocess.run(["git", "remote", "add", "origin", self.repo_url], 
                                  capture_output=True, text=True)
                                  
        if result.returncode != 0:
            print(f"{Colors.FAIL}❌ Failed to setup remote: {result.stderr}{Colors.ENDC}")
            return False
            
        # Set main branch
        result = subprocess.run(["git", "branch", "-M", "main"], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print(f"{Colors.WARNING}⚠️  Could not set main branch: {result.stderr}{Colors.ENDC}")
            
        # Push to GitHub
        print("Pushing to GitHub...")
        result = subprocess.run(["git", "push", "-u", "origin", "main"], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print(f"{Colors.FAIL}❌ Failed to push to GitHub: {result.stderr}{Colors.ENDC}")
            if "Authentication failed" in result.stderr:
                print(f"{Colors.WARNING}💡 Authentication tips:{Colors.ENDC}")
                print("   • Use personal access token as password")
                print("   • Or setup SSH keys for authentication")
                print("   • See: https://docs.github.com/en/authentication")
            return False
            
        print(f"{Colors.OKGREEN}✅ Successfully pushed to GitHub!{Colors.ENDC}")
        return True
        
    def print_success_message(self):
        """Print success message with next steps"""
        print(f"\n{Colors.OKGREEN}{Colors.BOLD}🎉 SUCCESS! Repository setup complete!{Colors.ENDC}")
        print(f"{Colors.OKCYAN}🌐 Repository URL: {self.repo_url}{Colors.ENDC}")
        
        print(f"\n{Colors.HEADER}📋 Next Steps:{Colors.ENDC}")
        print("1. 🌐 Visit your repository on GitHub")
        print("2. 🏷️  Add topics/tags for discoverability:")
        print("   rust, waf, reverse-proxy, web-security, owasp, ddos-protection")
        print("3. 🔄 Set up GitHub Actions for CI/CD (optional)")
        print("4. 🛡️  Configure branch protection rules (optional)")
        print("5. 📄 Add a LICENSE file (MIT recommended)")
        
        print(f"\n{Colors.HEADER}🔧 Local Development:{Colors.ENDC}")
        print("   cargo build --release")
        print("   ./target/release/waf-reverse-proxy --config config/config.yaml")
        
        print(f"\n{Colors.HEADER}🐳 Docker Deployment:{Colors.ENDC}")
        print("   docker-compose up -d")
        
        print(f"\n{Colors.HEADER}📊 Monitoring:{Colors.ENDC}")
        print("   • Grafana Dashboard: http://localhost:3000")
        print("   • Prometheus Metrics: http://localhost:9090/metrics")
        print("   • Admin API: http://localhost:8081/api")
        
        print(f"\n{Colors.OKGREEN}Happy coding! 🚀{Colors.ENDC}")
        
    def run(self):
        """Run the complete setup process"""
        try:
            self.print_header()
            
            if not self.check_prerequisites():
                sys.exit(1)
            
            # Try to create repository via GitHub API first
            if self.github_token:
                print(f"\n{Colors.OKCYAN}🔑 GitHub token found - attempting automatic setup{Colors.ENDC}")
                if self.create_github_repo():
                    print(f"{Colors.OKGREEN}✅ Repository ready for setup{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}⚠️  Falling back to manual repository setup{Colors.ENDC}")
                    self.get_repository_url()
            else:
                print(f"\n{Colors.WARNING}ℹ️  No GitHub token found - using manual setup{Colors.ENDC}")
                self.get_repository_url()
            
            if not self.initialize_git_repo():
                sys.exit(1)
                
            if not self.add_and_commit_files():
                sys.exit(1)
                
            if not self.setup_remote_and_push():
                sys.exit(1)
                
            self.print_success_message()
            
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}⚠️  Setup cancelled by user{Colors.ENDC}")
            sys.exit(1)
        except Exception as e:
            print(f"\n{Colors.FAIL}❌ Unexpected error: {e}{Colors.ENDC}")
            sys.exit(1)

def main():
    """Main entry point"""
    setup = GitSetup()
    setup.run()

if __name__ == "__main__":
    main()
