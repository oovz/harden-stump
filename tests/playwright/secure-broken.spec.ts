import { expect, test } from '@playwright/test'

const username = process.env.PLAYWRIGHT_E2E_USERNAME
const password = process.env.PLAYWRIGHT_E2E_PASSWORD
const brokenLibraryId = process.env.PLAYWRIGHT_CP9_BROKEN_LIBRARY_ID

// Broken secure library UI behavior
// This spec assumes a preconfigured secure library that is deliberately in an
// ENCRYPTION_BROKEN state and referenced via PLAYWRIGHT_CP9_BROKEN_LIBRARY_ID.
// It verifies that the CP9-aware UI surfaces a clear error state instead of
// crashing or showing a generic failure.

test.describe('broken secure library UI', () => {
	test.skip(
		!username || !password || !brokenLibraryId,
		'Missing PLAYWRIGHT_E2E_USERNAME, PLAYWRIGHT_E2E_PASSWORD, or PLAYWRIGHT_CP9_BROKEN_LIBRARY_ID',
	)

	async function login(page: Parameters<(typeof test)['extend']>[0]['page']) {
		await page.goto('/')
		// LoginOrClaimScene uses labeled inputs for username and password
		await page.getByLabel(/username/i).fill(username || '')
		await page.getByLabel(/password/i).fill(password || '')
		// Button text is typically "Log in" once the server is claimed
		await page.getByRole('button', { name: /log in/i }).click()
		// Wait for navigation away from auth screen
		await expect(page).not.toHaveURL(/\/auth/i)
	}

	test('shows broken-state error for secure library catalog', async ({ page }) => {
		await login(page)

		// Navigate directly to the broken secure library books tab
		await page.goto(`/libraries/${brokenLibraryId}/books`)

		// Books tab should render a clear error state for broken secure libraries
		await expect(page.getByText('Secure library error')).toBeVisible()
		await expect(
			page.getByText(
				/secure library is currently broken\. contact the server owner to restore from backup and rescan\./i,
			),
		).toBeVisible()
	})
})
