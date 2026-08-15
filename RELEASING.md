# Release operations

The SDK uses Release Please and npm trusted publishing. Tags, GitHub releases, workflow artifacts, and npm versions are immutable; never move or reuse them.

## Security boundaries

`.github/workflows/release-please.yml` has four jobs:

- `release` uses the `release-automation` environment and a repository-scoped GitHub App token to manage the release PR and GitHub release.
- `validate` checks the exact release tag and `main` ancestry, then installs dependencies and runs the SDK, API, package, and release-policy checks.
- `package` checks out the exact tag on a fresh runner, builds one lifecycle-script-disabled tarball, and uploads it with digest and artifact identity outputs.
- `publish` uses the `npm-publish` environment and OIDC. It checks out no source, verifies the exact artifact and package metadata, rechecks npm state, and publishes the tarball with provenance.

Every job fails closed unless both repository variables equal `true`:

- `NPM_TRUSTED_PUBLISHING_READY`
- `RELEASE_AUTOMATION_ENABLED`

## One-time activation

1. Create `release-automation` and `npm-publish` environments restricted to `main`.
2. Configure the 2K Bot credentials:
   - Repository variable `BOT_2K_APP_ID`: `4600682` (registered for inventory and administration)
   - Repository variable `BOT_2K_CLIENT_ID`: `Iv23ct8NTwJ8yiM1WYo3` (used to create the installation token)
   - Repository secret `BOT_2K_KEY`: the 2K Bot private key
3. Install 2K Bot on this repository with only Contents, Issues, and Pull requests read/write permissions. Issues write is required for Release Please's `autorelease:*` labels.
4. Configure the npm trusted publisher for `@lotor.dev/sdk`:

   ```text
   Owner:       2kims
   Repository:  lotor-sdk
   Workflow:    release-please.yml
   Environment: npm-publish
   ```

5. Protect `v*` tags from updates and deletion.
6. Keep repository auto-merge disabled. This private repository's current GitHub plan does not provide branch protection, so an operator must merge each release PR manually with squash only after `Validate PR title` and `Test` pass against the current `main`. If the repository is upgraded or made public, require both checks with strict up-to-date branches before reconsidering auto-merge.
7. Confirm both environments admit only the intended refs described above.
8. Enable `NPM_TRUSTED_PUBLISHING_READY`, then `RELEASE_AUTOMATION_ENABLED`.

Do not add an `NPM_TOKEN` fallback.

## Normal release

Conventional commits merged to `main` update the Release Please PR. After `Validate PR title` and `Test` pass against the current `main`, an operator squash-merges that PR; auto-merge is intentionally disabled. Its merge synchronizes `package.json`, `.release-please-manifest.json`, and `CHANGELOG.md`. Release Please then creates `v<version>` and the workflow validates, packages, and publishes that exact source. Stable releases use `latest`; prereleases use `next`.

## Recovery

Recovery is only for an existing non-draft GitHub release whose npm publication did not finish:

```bash
gh workflow run .github/workflows/release-please.yml \
  --repo 2kims/lotor-sdk \
  --ref main \
  -f tag=v0.1.0-rc.2
```

If npm already contains the exact version, recovery succeeds as a no-op. Never move a tag or rebuild an existing npm version.

## Emergency shutdown

```bash
gh variable delete RELEASE_AUTOMATION_ENABLED --repo 2kims/lotor-sdk
```

Also disable `NPM_TRUSTED_PUBLISHING_READY`, cancel active runs, and revoke the App key if credentials or OIDC configuration may be compromised.
