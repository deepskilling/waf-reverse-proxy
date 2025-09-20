#!/usr/bin/env python3
"""
WAF + Reverse Proxy - Main Setup Script
=======================================

This is the main setup script that orchestrates all setup tasks for the
WAF + Reverse Proxy project, including repository setup, deployment preparation,
and environment configuration.

Usage:
    python setup.py [command] [options]
    
Commands:
    init        Initialize the project (install dependencies, validate config)
    repo        Set up Git repository and push to GitHub
    deploy      Set up deployment environment (Docker, Kubernetes, monitoring)
    health      Run health checks on the system
    dev         Set up development environment
    all         Run all setup tasks
    
Options:
    --quiet     Suppress detailed output
    --json      Output results in JSON format (where applicable)
    
Examples:
    python setup.py init              # Initialize project
    python setup.py repo              # Set up repository
    python setup.py deploy --docker   # Set up Docker deployment
    python setup.py health --full     # Run full health check
    python setup.py all               # Run everything
    
Requirements:
    - Python 3.6+
    - Git (for repository setup)
    - Docker (for deployment setup)
    - Rust and Cargo (for building the project)
"""

import os
import sys
import json
import subprocess
import argparse
import shutil
from pathlib import Path
from datetime import datetime

# Add current directory to path to import our modules
sys.path.insert(0, str(Path(__file__).parent))

try:
    import setup_repo
    import setup_deployment
    import health_check
except ImportError as e:
    print(f"❌ Failed to import setup modules: {e}")
    print("   Make sure all setup scripts are in the same directory")
    sys.exit(1)

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

class MainSetup:
    """Main setup orchestrator"""
    
    def __init__(self, quiet=False, json_output=False):
        self.project_root = Path(__file__).parent.parent
        self.quiet = quiet
        self.json_output = json_output
        self.results = {}
        
    def log(self, message, level="info"):
        """Log message with appropriate color coding"""
        if self.json_output or self.quiet:
            return
            
        color = {
            "info": Colors.OKCYAN,
            "success": Colors.OKGREEN,
            "warning": Colors.WARNING,
            "error": Colors.FAIL,
            "header": Colors.HEADER + Colors.BOLD
        }.get(level, Colors.ENDC)
        
        print(f"{color}{message}{Colors.ENDC}")
        
    def print_header(self):
        """Print welcome header"""
        if not self.json_output:
            self.log("🚀 WAF + Reverse Proxy - Main Setup", "header")
            self.log("=" * 38, "header")
            
    def check_prerequisites(self):
        """Check system prerequisites"""
        self.log("\n🔍 Checking prerequisites...", "info")
        
        prereqs = {
            "python": {"cmd": [sys.executable, "--version"], "required": True},
            "git": {"cmd": ["git", "--version"], "required": False},
            "docker": {"cmd": ["docker", "--version"], "required": False},
            "cargo": {"cmd": ["cargo", "--version"], "required": False},
        }
        
        results = {}
        all_good = True
        
        for tool, config in prereqs.items():
            try:
                result = subprocess.run(config["cmd"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    version = result.stdout.strip().split('\n')[0]
                    results[tool] = {"available": True, "version": version}
                    self.log(f"✅ {tool}: {version}", "success")
                else:
                    results[tool] = {"available": False, "error": result.stderr.strip()}
                    if config["required"]:
                        self.log(f"❌ {tool}: Not working properly", "error")
                        all_good = False
                    else:
                        self.log(f"⚠️  {tool}: Not available (optional)", "warning")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                results[tool] = {"available": False, "error": "Not found"}
                if config["required"]:
                    self.log(f"❌ {tool}: Not installed", "error")
                    all_good = False
                else:
                    self.log(f"⚠️  {tool}: Not installed (optional)", "warning")
                    
        self.results['prerequisites'] = results
        return all_good
        
    def install_python_dependencies(self):
        """Install Python dependencies"""
        self.log("\n📦 Installing Python dependencies...", "info")
        
        requirements_file = self.project_root / "config" / "requirements.txt"
        if not requirements_file.exists():
            self.log("⚠️  requirements.txt not found, skipping", "warning")
            return True
            
        try:
            # Install core dependencies only (not optional ones)
            core_deps = ["requests>=2.28.0", "PyYAML>=6.0"]
            
            for dep in core_deps:
                result = subprocess.run([
                    sys.executable, "-m", "pip", "install", dep
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.log(f"✅ Installed: {dep.split('>=')[0]}", "success")
                else:
                    self.log(f"⚠️  Failed to install: {dep}", "warning")
                    
            return True
        except Exception as e:
            self.log(f"❌ Failed to install dependencies: {e}", "error")
            return False
            
    def validate_project_structure(self):
        """Validate project structure and files"""
        self.log("\n📁 Validating project structure...", "info")
        
        required_files = [
            "Cargo.toml",
            "config/config.yaml", 
            "src/main.rs",
            "README.md",
            "deployment/docker/Dockerfile",
            "deployment/docker/docker-compose.yml"
        ]
        
        optional_files = [
            "prometheus.yml",
            ".gitignore",
            "setup_repo.py",
            "setup_deployment.py", 
            "health_check.py"
        ]
        
        structure_results = {"required": {}, "optional": {}}
        all_required_present = True
        
        for file_path in required_files:
            file_obj = self.project_root / file_path
            exists = file_obj.exists()
            structure_results["required"][file_path] = exists
            
            if exists:
                self.log(f"✅ {file_path}", "success")
            else:
                self.log(f"❌ {file_path} (required)", "error")
                all_required_present = False
                
        for file_path in optional_files:
            file_obj = self.project_root / file_path
            exists = file_obj.exists()
            structure_results["optional"][file_path] = exists
            
            if exists:
                self.log(f"✅ {file_path}", "success")
            else:
                self.log(f"⚠️  {file_path} (optional)", "warning")
                
        self.results['project_structure'] = structure_results
        return all_required_present
        
    def init_project(self):
        """Initialize the project"""
        self.log("\n🎯 Initializing project...", "info")
        
        # Check prerequisites
        if not self.check_prerequisites():
            self.log("❌ Prerequisites check failed", "error")
            return False
            
        # Install dependencies
        if not self.install_python_dependencies():
            self.log("⚠️  Dependency installation had issues", "warning")
            
        # Validate structure
        if not self.validate_project_structure():
            self.log("❌ Project structure validation failed", "error")
            return False
            
        # Try to build the Rust project (if Cargo is available)
        if shutil.which("cargo"):
            self.log("\n🔨 Building Rust project...", "info")
            try:
                result = subprocess.run(["cargo", "check"], 
                                      cwd=self.project_root, capture_output=True, text=True)
                if result.returncode == 0:
                    self.log("✅ Rust project builds successfully", "success")
                else:
                    self.log(f"⚠️  Rust build has warnings/errors:", "warning")
                    if not self.quiet:
                        print(result.stderr[:500] + "..." if len(result.stderr) > 500 else result.stderr)
            except Exception as e:
                self.log(f"❌ Failed to build Rust project: {e}", "error")
                return False
        else:
            self.log("⚠️  Cargo not available, skipping build check", "warning")
            
        self.log("✅ Project initialization completed", "success")
        return True
        
    def setup_repository(self):
        """Set up Git repository"""
        self.log("\n📂 Setting up repository...", "info")
        
        try:
            git_setup = setup_repo.GitSetup()
            git_setup.run()
            self.results['repository_setup'] = {"status": "success"}
            return True
        except Exception as e:
            self.log(f"❌ Repository setup failed: {e}", "error")
            self.results['repository_setup'] = {"status": "failed", "error": str(e)}
            return False
            
    def setup_deployment_env(self, deployment_type="docker"):
        """Set up deployment environment"""
        self.log(f"\n🐳 Setting up {deployment_type} deployment...", "info")
        
        try:
            deploy_setup = setup_deployment.DeploymentSetup()
            
            if deployment_type == "docker":
                success = deploy_setup.setup_docker_deployment()
            elif deployment_type == "kubernetes":
                success = deploy_setup.generate_kubernetes_manifests()
            elif deployment_type == "monitoring":
                success = deploy_setup.setup_monitoring_stack()
            elif deployment_type == "all":
                success = (
                    deploy_setup.validate_configuration() and
                    deploy_setup.setup_docker_deployment() and
                    deploy_setup.generate_kubernetes_manifests() and
                    deploy_setup.setup_monitoring_stack()
                )
            else:
                self.log(f"❌ Unknown deployment type: {deployment_type}", "error")
                return False
                
            self.results[f'{deployment_type}_deployment'] = {"status": "success" if success else "failed"}
            return success
        except Exception as e:
            self.log(f"❌ Deployment setup failed: {e}", "error")
            self.results[f'{deployment_type}_deployment'] = {"status": "failed", "error": str(e)}
            return False
            
    def run_health_check(self, check_type="full"):
        """Run health checks"""
        self.log("\n🏥 Running health checks...", "info")
        
        try:
            checker = health_check.HealthChecker(quiet=self.quiet, json_output=False)
            
            if check_type == "full":
                checks = ['service', 'config', 'performance', 'security', 'endpoints']
            else:
                checks = [check_type]
                
            report = checker.run_health_check(checks)
            self.results['health_check'] = report
            
            return report['overall_status'] == 'healthy'
        except Exception as e:
            self.log(f"❌ Health check failed: {e}", "error")
            self.results['health_check'] = {"status": "failed", "error": str(e)}
            return False
            
    def setup_development_environment(self):
        """Set up development environment"""
        self.log("\n💻 Setting up development environment...", "info")
        
        # Create useful development directories
        dev_dirs = ["tests", "docs", "scripts", "examples"]
        for dir_name in dev_dirs:
            dir_path = self.project_root / dir_name
            if not dir_path.exists():
                dir_path.mkdir()
                self.log(f"📁 Created: {dir_name}/", "success")
                
        # Create a simple test script
        test_script = self.project_root / "scripts" / "test.sh"
        if not test_script.exists():
            test_script.write_text("""#!/bin/bash
# Simple test script for WAF + Reverse Proxy

echo "🧪 Running tests..."

# Build the project
echo "Building Rust project..."
cargo build --release

# Run unit tests
echo "Running unit tests..."
cargo test

# Basic health check
echo "Running health check..."
python3 health_check.py --quiet

echo "✅ Tests completed!"
""")
            test_script.chmod(0o755)
            self.log("✅ Created test script", "success")
            
        # Create example configuration
        example_config = self.project_root / "examples" / "minimal.yaml"
        if not example_config.exists():
            example_config.write_text("""# Minimal WAF + Reverse Proxy Configuration
server:
  host: "127.0.0.1"
  port: 8080

waf:
  enabled: true
  mode: "block"

proxy:
  upstreams:
    example:
      servers:
        - url: "http://httpbin.org"
          weight: 1
      load_balancer: "round_robin"
  
  routes:
    - host: "*"
      path: "/"
      upstream: "example"

logging:
  level: "info"
  format: "pretty"

metrics:
  enabled: true
""")
            self.log("✅ Created example configuration", "success")
            
        self.log("✅ Development environment ready", "success")
        return True
        
    def generate_final_report(self):
        """Generate final setup report"""
        timestamp = datetime.now().isoformat()
        
        # Count successes and failures
        total_tasks = 0
        successful_tasks = 0
        
        for task, result in self.results.items():
            total_tasks += 1
            if isinstance(result, dict):
                if result.get('status') == 'success' or result.get('overall_status') == 'healthy':
                    successful_tasks += 1
            else:
                successful_tasks += 1  # Assume success if no specific status
                
        success_rate = (successful_tasks / total_tasks * 100) if total_tasks > 0 else 0
        overall_status = "success" if success_rate >= 80 else "partial" if success_rate >= 50 else "failed"
        
        report = {
            "timestamp": timestamp,
            "overall_status": overall_status,
            "success_rate": round(success_rate, 1),
            "summary": {
                "total_tasks": total_tasks,
                "successful_tasks": successful_tasks,
                "failed_tasks": total_tasks - successful_tasks
            },
            "results": self.results
        }
        
        return report
        
    def print_final_status(self, report):
        """Print final status and next steps"""
        if self.json_output:
            print(json.dumps(report, indent=2))
            return
            
        self.log(f"\n📋 Setup Summary", "header")
        self.log(f"Overall Status: {report['overall_status'].upper()}", 
                "success" if report['overall_status'] == 'success' else 'warning')
        self.log(f"Success Rate: {report['success_rate']}%", "info")
        self.log(f"Tasks: {report['summary']['successful_tasks']}/{report['summary']['total_tasks']} completed", "info")
        
        if report['overall_status'] == 'success':
            self.log("\n🎉 Setup completed successfully!", "success")
            self.log("\n📋 Next Steps:", "header")
            self.log("1. 🔨 Build the project: cargo build --release", "info")
            self.log("2. 🚀 Start the service: ./target/release/waf-reverse-proxy --config config/config.yaml", "info") 
            self.log("3. 🧪 Run health check: python3 scripts/health_check.py --full", "info")
            self.log("4. 🐳 Or use Docker: docker-compose -f deployment/docker/docker-compose.yml up -d", "info")
            self.log("5. 🌐 Visit http://localhost:8080 to test", "info")
        else:
            self.log("\n⚠️  Setup completed with some issues", "warning")
            self.log("Review the output above for details", "warning")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="WAF + Reverse Proxy Main Setup")
    parser.add_argument("command", nargs="?", default="init",
                       choices=["init", "repo", "deploy", "health", "dev", "all"],
                       help="Setup command to run")
    parser.add_argument("--docker", action="store_true", help="Set up Docker deployment")
    parser.add_argument("--kubernetes", action="store_true", help="Set up Kubernetes deployment") 
    parser.add_argument("--monitoring", action="store_true", help="Set up monitoring stack")
    parser.add_argument("--quiet", action="store_true", help="Suppress detailed output")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    
    args = parser.parse_args()
    
    setup = MainSetup(quiet=args.quiet, json_output=args.json)
    setup.print_header()
    
    success = True
    
    try:
        if args.command == "init":
            success = setup.init_project()
            
        elif args.command == "repo":
            success = setup.setup_repository()
            
        elif args.command == "deploy":
            if args.docker:
                success = setup.setup_deployment_env("docker")
            elif args.kubernetes:
                success = setup.setup_deployment_env("kubernetes")
            elif args.monitoring:
                success = setup.setup_deployment_env("monitoring")
            else:
                success = setup.setup_deployment_env("all")
                
        elif args.command == "health":
            success = setup.run_health_check("full")
            
        elif args.command == "dev":
            success = setup.setup_development_environment()
            
        elif args.command == "all":
            success = (
                setup.init_project() and
                setup.setup_development_environment() and
                setup.setup_deployment_env("all")
            )
            # Don't include repo setup in "all" as it requires user interaction
            
        # Generate final report
        report = setup.generate_final_report()
        setup.print_final_status(report)
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        setup.log("\n⚠️  Setup cancelled by user", "warning")
        sys.exit(1)
    except Exception as e:
        setup.log(f"\n❌ Unexpected error: {e}", "error")
        sys.exit(1)

if __name__ == "__main__":
    main()
