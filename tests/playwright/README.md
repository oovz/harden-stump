# E2E Tests (Playwright)

This directory contains end-to-end tests for secure library functionality using Playwright.

## Prerequisites

1. **Running Stump Server**: The server must be running at the configured `PLAYWRIGHT_BASE_URL`
2. **Test User Account**: A user account with appropriate permissions
3. **Secure Library**: An encrypted secure library with at least one CBZ file containing images
4. **Completed Secure Scan**: The secure library scan must have finished successfully

## Environment Variables

### Core Variables (Required)

| Variable | Description | Default |
|----------|-------------|---------|
| `PLAYWRIGHT_E2E_USERNAME` | Test user username | *required* |
| `PLAYWRIGHT_E2E_PASSWORD` | Test user password | *required* |
| `PLAYWRIGHT_SECURE_LIBRARY_ID` | UUID of encrypted secure library | *required* |
| `PLAYWRIGHT_BASE_URL` | Server URL | `http://localhost:10801` |
| `PLAYWRIGHT_WORKERS` | Number of parallel workers | `1` |

### secure-unlock.spec.ts (Additional)

| Variable | Description | Required |
|----------|-------------|----------|
| `PLAYWRIGHT_SECURE_ONLY_SEARCH` | Search term unique to secure library content (for global search exclusion test) | Optional |

### secure-delete.spec.ts

| Variable | Description | Required |
|----------|-------------|----------|
| `PLAYWRIGHT_E2E_IS_OWNER` | Set to `true` if test user is library owner | For owner tests |
| `PLAYWRIGHT_E2E_NONOWNER_USERNAME` | Non-owner user username | For non-owner tests |
| `PLAYWRIGHT_E2E_NONOWNER_PASSWORD` | Non-owner user password | For non-owner tests |

### secure-broken.spec.ts

| Variable | Description | Required |
|----------|-------------|----------|
| `PLAYWRIGHT_CP9_BROKEN_LIBRARY_ID` | UUID of a secure library in `ENCRYPTION_BROKEN` state | Yes |

## Example .env File

```bash
# Core (required for most tests)
PLAYWRIGHT_E2E_USERNAME=""
PLAYWRIGHT_E2E_PASSWORD=""
PLAYWRIGHT_SECURE_LIBRARY_ID=""
PLAYWRIGHT_BASE_URL="http://localhost:10801"

# secure-unlock extras
PLAYWRIGHT_SECURE_ONLY_SEARCH="unique-secure-book-title"

# secure-delete (owner tests)
PLAYWRIGHT_E2E_IS_OWNER="true"

# secure-delete (non-owner tests)
PLAYWRIGHT_E2E_NONOWNER_USERNAME="viewer"
PLAYWRIGHT_E2E_NONOWNER_PASSWORD="viewerpassword"

# secure-broken (requires deliberately broken library)
PLAYWRIGHT_CP9_BROKEN_LIBRARY_ID=<uuid-of-broken-library>
```

## Running Tests

```bash
# Run all e2e tests
yarn test:e2e

# Run specific test file
yarn playwright test tests/playwright/secure-unlock.spec.ts

# Run with UI mode (interactive)
yarn playwright test --ui

# Run headed (see browser)
yarn playwright test --headed

# Debug mode
yarn playwright test --debug
```

## Test Files

| File | Description |
|------|-------------|
| `secure-unlock.spec.ts` | Unlock flow, browsing, reader, heartbeat, session |
| `secure-delete.spec.ts` | Secure item deletion (owner/non-owner) |
| `secure-broken.spec.ts` | Broken secure library error UI |

## Skipped Tests

Tests are automatically skipped if required environment variables are missing. The skip message indicates which variables are needed.

## Troubleshooting

### "Element is outside of the viewport"

The secure reader toolbar (`ReaderHeader`) is `position: fixed` with a framer-motion animation (`y: -100%` when hidden). Standard Playwright clicks fail because:
1. `scrollIntoViewIfNeeded()` doesn't work for fixed-position elements
2. The animation may not complete before the click

**Solution**: Use JavaScript click via `evaluate()`:
```typescript
await page.keyboard.press('Space')  // Toggle toolbar visible
await backLink.waitFor({ state: 'visible', timeout: 5000 })
await page.waitForTimeout(300)  // Wait for 0.2s animation
await backLink.evaluate((el: HTMLElement) => el.click())
```

### Tests timing out on reader operations

The secure reader decrypts content client-side which can be slow. Tests use generous timeouts (60s) for reader operations.

### Password re-prompt issues

The LMK (Library Master Key) is stored in-memory. Tests use React Router navigation (`navigate()`) instead of `window.location.assign()` to preserve the LMK state.
