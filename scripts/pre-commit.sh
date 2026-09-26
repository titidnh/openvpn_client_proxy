#!/bin/bash
# Pre-commit hook for shell script linting
# Install: cp scripts/pre-commit.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

set -e

echo "🔍 Running pre-commit lint checks..."

# Check for shellcheck
if ! command -v shellcheck &> /dev/null; then
    echo "⚠️  shellcheck not installed - skipping lint checks"
    echo "   Install with: sudo apt-get install shellcheck (Ubuntu/Debian)"
    exit 0
fi

# Get staged shell files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(sh)$' || true)

if [ -z "$STAGED_FILES" ]; then
    echo "✅ No shell scripts to check"
    exit 0
fi

LINT_FAILED=0

# Run shellcheck on staged files
for file in $STAGED_FILES; do
    if [ -f "$file" ]; then
        echo "  Checking: $file"
        if ! shellcheck "$file"; then
            LINT_FAILED=1
        fi
    fi
done

if [ $LINT_FAILED -eq 1 ]; then
    echo ""
    echo "❌ Lint checks failed!"
    echo "   Fix issues or use: git commit --no-verify (not recommended)"
    exit 1
fi

echo "✅ Lint checks passed"
exit 0
