#!/bin/bash
# scripts/deploy_production_opsec.sh

echo "Initiating Brone God-Mode OpSec Pre-Flight Sweep..."

# Stage all changes
git add -A

# Sweep 1: Check for staged .env files
if git diff --cached --name-only | grep -E '\.env'; then
    echo "CRITICAL FAULT: .env file detected in staging area."
    git reset
    exit 1
fi

# Sweep 2: Check for raw private keys being ADDED (ignoring deletions and this script)
# -U0 removes context lines. grep '^\+' only looks at newly added lines. grep -v '+++' ignores file headers.
if git diff --cached -U0 -- . ':!scripts/deploy_production_opsec.sh' | grep '^\+' | grep -v '+++' | grep -E '-----BEGIN PRIVATE KEY-----|RSA_PRIVATE|HPKE_PRIVATE'; then
    echo "CRITICAL FAULT: Raw private key detected in staged diff."
    git reset
    exit 1
fi

echo "Sweeps passed. Executing Ghost Commit..."
export GIT_COMMITTER_NAME="brone-deploy"
export GIT_AUTHOR_NAME="brone-deploy"
export GIT_COMMITTER_EMAIL="deploy@localhost"
export GIT_AUTHOR_EMAIL="deploy@localhost"

FLAT_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
export GIT_AUTHOR_DATE="$FLAT_DATE"
export GIT_COMMITTER_DATE="$FLAT_DATE"

git commit -m "chore(core): finalize phase 4 zero-knowledge ledger and enclave bridging"

echo "Ghost Commit successful. Pushing to origin..."
git push origin main

echo "Deployment secure and complete."