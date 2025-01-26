# Release Process

This document outlines the steps for creating and publishing a new release.

## Prerequisites

Install required tools:

```bash
cargo install git-cliff cargo-edit
```

## Creating a Release

1. Update main branch:

```bash
git checkout main
git pull origin main
```

2. Update version:

```bash
# Set new version in Cargo.toml - replace 1.2.0 with target version
cargo set-version 1.2.0
cargo check  # Ensure everything builds correctly
```

3. Generate changelog:

```bash
# Generate/update for new version
git cliff --prepend CHANGELOG.md --unreleased --tag v1.2.0
```

4. Create release branch and commit:

```bash
git checkout -b release/v1.2.0
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore(release): prepare for v1.2.0"
git push origin release/v1.2.0
```

5. Create PR from release branch to main and get it reviewed/merged

## Publishing

After merge to main:

1. Tag release:

```bash
git checkout main
git pull origin main
git tag -a v1.2.0 -m "Release v1.2.0"
git push origin v1.2.0
```

2. Publish to crates.io:

```bash
# Verify package contents
cargo package

# Login if haven't already
cargo login

# Publish package
cargo publish

# If using workspace, cd to package directory first
cd my-package  # if needed
cargo publish
```

3. Clean up:

```bash
git branch -d release/v1.2.0
```

## Notes

- Use conventional commits (feat:, fix:, etc.) for better changelog organization
- Version numbers in above commands should be replaced with actual target version
- If using workspaces, publish command must be run from package directory
