#!/bin/bash
# compare_branches.sh - Compare the code between two branches in this repository
#
# Usage:
#   ./scripts/compare_branches.sh <branch1> <branch2> [options]
#
# Options:
#   --stat          Show a summary of changed files (default)
#   --diff          Show full diff output
#   --files         List only the changed file names
#   --log           Show commits in branch2 that are not in branch1
#   --help          Show this help message
#
# Examples:
#   ./scripts/compare_branches.sh master dev
#   ./scripts/compare_branches.sh master dev --diff
#   ./scripts/compare_branches.sh base mee --log
#   ./scripts/compare_branches.sh SYN_CC SYN_ECC --files

set -e

usage() {
    sed -n '2,/^[^#]/{ /^#/p }' "$0" | sed 's/^# \?//'
    exit 1
}

if [ "$1" = "--help" ] || [ $# -lt 2 ]; then
    usage
fi

BRANCH1="$1"
BRANCH2="$2"
MODE="${3:---stat}"

# Verify that the repository is a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "Error: Not inside a git repository." >&2
    exit 1
fi

# Resolve a branch name: prefer local, fall back to origin/<branch>
resolve_branch() {
    local branch="$1"
    if git rev-parse --verify "$branch" > /dev/null 2>&1; then
        echo "$branch"
    elif git rev-parse --verify "origin/$branch" > /dev/null 2>&1; then
        echo "origin/$branch"
    else
        echo ""
    fi
}

# Verify both branches exist and resolve to refs
RESOLVED1=$(resolve_branch "$BRANCH1")
RESOLVED2=$(resolve_branch "$BRANCH2")

for i in 1 2; do
    eval "branch=\$BRANCH$i"
    eval "resolved=\$RESOLVED$i"
    if [ -z "$resolved" ]; then
        echo "Error: Branch '$branch' does not exist locally or in origin." >&2
        echo "Available branches:" >&2
        git branch -a | sed 's|remotes/origin/||' | sed 's|^ *||' | sort -u >&2
        exit 1
    fi
done

echo "=== Comparing branches: '$BRANCH1' vs '$BRANCH2' ==="
echo ""

case "$MODE" in
    --stat)
        echo "--- Changed files summary ---"
        git --no-pager diff --stat "$RESOLVED1".."$RESOLVED2"
        ;;
    --diff)
        echo "--- Full diff ---"
        git --no-pager diff "$RESOLVED1".."$RESOLVED2"
        ;;
    --files)
        echo "--- Changed files ---"
        git --no-pager diff --name-only "$RESOLVED1".."$RESOLVED2"
        ;;
    --log)
        echo "--- Commits in '$BRANCH2' not in '$BRANCH1' ---"
        git --no-pager log --oneline "$RESOLVED1".."$RESOLVED2"
        ;;
    *)
        echo "Error: Unknown option '$MODE'" >&2
        usage
        ;;
esac
