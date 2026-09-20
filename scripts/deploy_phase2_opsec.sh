#!/usr/bin/env bash
set -euo pipefail

echo "===================================================================="
echo "🔒 [OPSEC DEPLOYMENT] Initiating Phase 2 Zero-Knowledge Pre-Commit Sweep"
echo "===================================================================="

# 1. Stage Files
echo "--> Staging all modified files..."
git add .

# 2. The Pre-Commit Sweep: Differentiate between filenames and file content

# Sweep 1: Check if any .env files are staged
if git diff --cached --name-only | grep -E "\.env" > /dev/null 2>&1; then
    echo "===================================================================="
    echo "🚨 [FATAL LEAK] .env file detected in staged changes!"
    echo "===================================================================="
    echo "Staged files contain .env files:"
    git diff --cached --name-only | grep -E "\.env" || true
    echo "--------------------------------------------------------------------"
    echo "--> Aborting deployment. Unstaging all files..."
    git reset
    exit 1
fi

# Sweep 2: Check content for raw private keys
if git diff --cached | grep -E "-----BEGIN PRIVATE KEY-----|RSA_PRIVATE|HPKE_PRIVATE" > /dev/null 2>&1; then
    echo "===================================================================="
    echo "🚨 [FATAL LEAK] Raw private keys detected in staged code!"
    echo "===================================================================="
    echo "Matching patterns found in staged diff:"
    git diff --cached | grep -E -n "-----BEGIN PRIVATE KEY-----|RSA_PRIVATE|HPKE_PRIVATE" || true
    echo "--------------------------------------------------------------------"
    echo "--> Aborting deployment. Unstaging all files..."
    git reset
    exit 1
fi

echo "✅ [OPSEC PASSED] No raw private keys or .env files detected."

# 3. The Ghost Commit: Execute commit using flattened UTC timestamp & generic author
echo "--> Executing Anonymous Ghost Commit..."
CURRENT_UTC_TIME="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

GIT_COMMITTER_NAME="brone-deploy" \
GIT_COMMITTER_EMAIL="null@brone.network" \
GIT_AUTHOR_NAME="brone-deploy" \
GIT_AUTHOR_EMAIL="null@brone.network" \
GIT_COMMITTER_DATE="$CURRENT_UTC_TIME" \
GIT_AUTHOR_DATE="$CURRENT_UTC_TIME" \
git commit -m "refactor: phase 2 network anonymity, ohttp, and chaffing"

echo "✅ Commit successfully created under anonymous profile 'brone-deploy'."

# 4. The Push
echo "--> Pushing to origin main..."
git push origin main

echo "===================================================================="
echo "🚀 [OPSEC DEPLOYMENT COMPLETE] Phase 2 successfully pushed to main."
echo "===================================================================="
