# CI/Lint/Tests Documentation

This commit introduces quality gates and automated testing for the project.

## Configuration Files Added

### 1. `.shellcheckrc`
ShellCheck configuration with strict rules. Key settings:
- `enable=all`: Enable all optional checks
- Ignores specific checks that cause false positives in this codebase

Run locally:
```bash
shellcheck scripts/*.sh lib/*.sh start.sh
```

### 2. `.shfmtrc`
Shell script formatter configuration. Standards:
- 4-space indentation
- Consistent formatting across all scripts
- Binary operators at line beginning
- Space after redirect operators

Run locally:
```bash
shfmt -d scripts/*.sh lib/*.sh  # Dry-run (show differences)
shfmt -i 4 -w scripts/*.sh      # Write formatted version
```

### 3. `.github/workflows/lint-and-test.yml`
GitHub Actions CI pipeline with three gates:

**ShellCheck**: Validates script correctness
- Runs on all `.sh` files
- Blocks PR if shellcheck warnings found
- Catches common shell scripting mistakes

**shfmt**: Validates code style consistency
- Checks all shell scripts for format compliance
- Currently warnings-only (doesn't block yet)
- Will enforce consistency

**BATS Tests**: Unit and integration tests
- Located in `tests/` directory
- Tests critical functions from `lib/` modules
- Validates initialization, blocklist logic, etc.

### 4. `scripts/pre-commit.sh`
Optional local git hook for quick lint feedback before commit.

Install:
```bash
cp scripts/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Then shellcheck runs automatically before each commit.

## Test Files Added

### `tests/common.bats`
Tests for `lib/common.sh`:
- Module loading
- Environment variable initialization
- Log functions
- Configuration validation

### `tests/dns_blocklist.bats`
Tests for `lib/dns_blocklist.sh`:
- Module loading
- Blocklist size validation
- Allowlist parsing
- DNS variable initialization

## Running Checks Locally

### ShellCheck
```bash
# Check all scripts
shellcheck *.sh lib/*.sh scripts/*.sh

# Check with strict settings
shellcheck -S style -S warning lib/dns_blocklist.sh
```

### shfmt
```bash
# Check formatting (dry-run)
shfmt -d *.sh lib/*.sh

# Auto-fix formatting
shfmt -i 4 -w *.sh lib/*.sh
```

### BATS Tests
```bash
# Install bats (Ubuntu/Debian)
sudo apt-get install bats

# Run all tests
bats tests/*.bats

# Run specific test file
bats tests/common.bats

# Run with verbose output
bats tests/*.bats --trace
```

## CI Pipeline

The GitHub Actions workflow runs on:
- All pushes to `main`, `develop`, and `features/**` branches
- All pull requests to `main` and `develop`

### Pipeline Flow
1. **ShellCheck** → Validates script correctness (BLOCKS if failed)
2. **shfmt** → Checks format consistency (warnings only)
3. **BATS** → Runs unit/integration tests (BLOCKS if failed)
4. **Summary** → Reports overall status

## Best Practices

### Before Committing
1. Run `shellcheck` on modified scripts
2. Run `shfmt -d` to check formatting
3. Run `bats` tests if you modified core functionality

### For Contributors
- Install the pre-commit hook to catch issues early
- Follow the formatting rules in `.shfmtrc`
- Add BATS tests for new functions in `lib/` modules
- Don't ignore shellcheck warnings without good reason

### For Reviewers
- Check GitHub Actions CI status on PRs
- Lint failures must be fixed before merge
- Test results must pass for deployment

## Key Metrics

This commit establishes:
- **Code Quality Gate**: 100% ShellCheck pass rate required
- **Format Consistency**: Automated via shfmt config
- **Test Coverage**: Unit and integration tests for critical paths
- **Automation**: GitHub Actions runs all checks on every PR

---

**Note**: This is Phase S3 of the maintenance plan:
"Qualité automatique (CI) - Phase S3"
