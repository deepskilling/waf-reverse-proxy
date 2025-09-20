# Contributing to WAF + Reverse Proxy

![Deepskilling](https://img.shields.io/badge/powered%20by-deepskilling-blue)
[![Contributors Welcome](https://img.shields.io/badge/contributors-welcome-brightgreen.svg)](CONTRIBUTING.md)

Thank you for your interest in contributing to the **WAF + Reverse Proxy** project by **Deepskilling**! We welcome contributions from the community and are excited to work with you.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Contribution Guidelines](#contribution-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Guidelines](#issue-guidelines)
- [Community](#community)

## 🤝 Code of Conduct

This project adheres to a **Code of Conduct** that all contributors are expected to follow. Please be respectful, inclusive, and professional in all interactions.

### Our Standards

- **Be Respectful**: Treat everyone with respect and kindness
- **Be Inclusive**: Welcome people of all backgrounds and experience levels
- **Be Collaborative**: Work together constructively
- **Be Professional**: Maintain professional communication
- **Be Patient**: Help newcomers learn and grow

## 🛠️ How to Contribute

### Types of Contributions We Welcome

- 🐛 **Bug Reports**: Help us identify and fix issues
- ✨ **Feature Requests**: Suggest new functionality
- 📝 **Documentation**: Improve docs, guides, and examples
- 🧪 **Tests**: Add or improve test coverage
- 🔧 **Code**: Fix bugs or implement features
- 🎨 **UI/UX**: Improve user interface and experience
- 📊 **Performance**: Optimize performance and efficiency

### First Time Contributing?

Look for issues labeled with:
- `good first issue` - Perfect for newcomers
- `help wanted` - We need community help
- `documentation` - Documentation improvements
- `beginner friendly` - Easy to start with

## 🚀 Development Setup

### Prerequisites

- **Rust** 1.70+ with Cargo
- **Git** 2.30+
- **Docker** (optional, for testing)
- **Python** 3.8+ (for automation scripts)

### Setup Steps

```bash
# 1. Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/waf-reverse-proxy.git
cd waf-reverse-proxy

# 2. Set up upstream remote
git remote add upstream https://github.com/deepskilling/waf-reverse-proxy.git

# 3. Install dependencies
cargo build

# 4. Run tests to ensure everything works
cargo test

# 5. Install Python dependencies for scripts
pip install -r requirements.txt
```

### Development Workflow

```bash
# 1. Create a feature branch
git checkout -b feature/your-feature-name

# 2. Make your changes
# ... edit files ...

# 3. Run tests and checks
cargo test                    # Run tests
cargo clippy -- -D warnings  # Check for issues
cargo fmt                    # Format code

# 4. Commit your changes
git add .
git commit -m "feat: add your feature description"

# 5. Push to your fork
git push origin feature/your-feature-name

# 6. Create a Pull Request
```

## 📜 Contribution Guidelines

### Code Style

- **Follow Rust conventions**: Use `cargo fmt` and `cargo clippy`
- **Write clear code**: Prefer readability over cleverness
- **Add comments**: Document complex logic and public APIs
- **Use meaningful names**: Variables, functions, and types should be descriptive

### Commit Message Format

We follow the [Conventional Commits](https://conventionalcommits.org/) specification:

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```bash
feat(waf): add OWASP rule for SQL injection detection
fix(proxy): resolve connection pooling memory leak
docs(setup): update installation instructions
test(security): add unit tests for JWT validation
```

### Documentation

- **Update README.md** if adding new features
- **Document public APIs** with Rust doc comments
- **Update SETUP.md** for configuration changes
- **Add examples** for new functionality
- **Include inline comments** for complex logic

### Testing

- **Write tests** for new features and bug fixes
- **Run full test suite**: `cargo test`
- **Test edge cases** and error conditions
- **Add integration tests** for major features
- **Ensure CI passes** before submitting PR

## 🔄 Pull Request Process

### Before Submitting

1. **Sync with upstream**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run quality checks**:
   ```bash
   cargo test           # All tests pass
   cargo clippy         # No clippy warnings
   cargo fmt --check    # Code is formatted
   ```

3. **Update documentation** if needed
4. **Add tests** for new functionality
5. **Ensure clean commit history**

### PR Requirements

- ✅ **Descriptive title** and clear description
- ✅ **Link related issues** using keywords (fixes #123)
- ✅ **All tests passing** (CI checks green)
- ✅ **Code review approval** from maintainers
- ✅ **Documentation updated** if needed
- ✅ **No conflicts** with main branch

### PR Template

When creating a PR, please include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added and passing
```

## 🐛 Issue Guidelines

### Bug Reports

Please include:
- **Clear title** and description
- **Steps to reproduce** the issue
- **Expected vs actual behavior**
- **Environment details** (OS, Rust version, etc.)
- **Error messages** or stack traces
- **Minimal reproduction case** if possible

### Feature Requests

Please include:
- **Clear description** of the proposed feature
- **Use case and motivation**
- **Proposed implementation** (if you have ideas)
- **Potential impact** on existing functionality
- **Alternative solutions** you've considered

### Issue Labels

- `bug` - Something isn't working
- `enhancement` - New feature or request
- `documentation` - Documentation improvements
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention needed
- `security` - Security-related issues
- `performance` - Performance improvements

## 🌟 Recognition

Contributors are recognized in several ways:

- **Contributors section** in README.md
- **Release notes** mention significant contributions  
- **Hall of Fame** for major contributors
- **Deepskilling swag** for active contributors (when available)

## 📞 Community & Support

### Getting Help

- **GitHub Discussions**: Ask questions and share ideas
- **GitHub Issues**: Report bugs and request features
- **Documentation**: Check [SETUP.md](SETUP.md) for detailed guides

### Community Channels

- **GitHub**: Primary platform for development
- **Discussions**: Community Q&A and brainstorming
- **Issues**: Bug tracking and feature requests

### Maintainer Contact

For questions about contributing or the project direction, feel free to reach out to the Deepskilling team through GitHub issues or discussions.

---

## 🏆 Hall of Fame

*Contributors who have made significant impact on the project will be recognized here.*

---

## 📄 License

By contributing to this project, you agree that your contributions will be licensed under the same [MIT License](LICENSE) that covers the project.

---

**Thank you for contributing to WAF + Reverse Proxy by Deepskilling!**

*Your contributions help make web applications more secure and performant for everyone.*

---

© 2025 Deepskilling. All rights reserved.
