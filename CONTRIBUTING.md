# Contributing to Jarvis Messenger

Thank you for your interest in contributing to Jarvis Messenger! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming environment
- Follow professional communication standards

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Git for version control
- Terminal/command line access

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/orpheus497/jarvisapp.git
cd jarvisapp

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pip install pre-commit
pre-commit install
```

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes

- Follow existing code style and patterns
- Add docstrings to all public methods
- Include type hints where appropriate
- Write tests for new functionality

### 3. Run Quality Checks

```bash
# Format code
black src/jarvis

# Lint code
ruff check src/jarvis --fix

# Type check
mypy src/jarvis

# Run tests
pytest tests/

# Check coverage
pytest --cov=src/jarvis tests/
```

### 4. Commit Your Changes

```bash
# Stage changes
git add -A

# Commit with descriptive message
git commit -m "feat: Add new feature"
```

Commit message format:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `refactor:` Code refactoring
- `test:` Test additions/changes
- `chore:` Build/tooling changes

### 5. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub with:
- Clear description of changes
- Reference to related issues
- Screenshots/examples if applicable

## Code Style Guidelines

### Python Code

- Follow PEP 8 style guide
- Use Black for automatic formatting (100 char line length)
- Use type hints for function signatures
- Write descriptive docstrings (Google style)

Example:
```python
def validate_port(port: int) -> bool:
    """
    Validate a port number.

    Args:
        port: Port number to validate

    Returns:
        True if valid (1024-65535), False otherwise
    """
    return 1024 <= port <= 65535
```

### Documentation

- Use Markdown for documentation files
- Include code examples where helpful
- Keep language clear and concise
- Update CHANGELOG.md for all changes

## Testing Guidelines

### Writing Tests

- Place unit tests in `tests/unit/`
- Place integration tests in `tests/integration/`
- Use descriptive test names
- One assertion per test when possible
- Use pytest fixtures from conftest.py

Example:
```python
def test_validate_port_accepts_valid_ports():
    """Test that valid port numbers are accepted."""
    assert validate_port(5000) is True
    assert validate_port(8080) is True
```

### Test Coverage

- Aim for 80%+ code coverage
- Focus on critical paths first
- Test edge cases and error conditions
- Use `pytest --cov` to check coverage

## Security Guidelines

- Never commit secrets or passwords
- Use secure cryptographic primitives
- Validate all user inputs
- Follow principle of least privilege
- Report security issues privately

## Pull Request Checklist

Before submitting a pull request, ensure:

- [ ] Code follows project style guidelines
- [ ] All tests pass (`pytest tests/`)
- [ ] New code has test coverage
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated
- [ ] Pre-commit hooks pass
- [ ] No merge conflicts with main branch

## Getting Help

- Check existing documentation
- Review closed issues for similar problems
- Ask questions in GitHub discussions
- Be specific about your environment and issue

## Project Structure

```
jarvisapp/
├── src/jarvis/          # Main application code
│   ├── crypto.py        # Cryptography primitives
│   ├── protocol.py      # Network protocol
│   ├── network.py       # P2P networking
│   ├── server.py        # Background server
│   ├── ui.py            # Textual UI
│   └── ...
├── tests/               # Test suite
│   ├── unit/            # Unit tests
│   ├── integration/     # Integration tests
│   └── conftest.py      # Pytest fixtures
├── docs/                # Documentation
├── .dev-docs/           # Development documentation
└── pyproject.toml       # Project configuration
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Attribution

All contributions are appreciated and will be attributed in the project's commit history and release notes.

Created by orpheus497
