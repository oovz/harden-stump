import { expect, test } from '@playwright/test'

const username = process.env.PLAYWRIGHT_E2E_USERNAME
const password = process.env.PLAYWRIGHT_E2E_PASSWORD
const secureLibraryId = process.env.PLAYWRIGHT_SECURE_LIBRARY_ID
const isOwner = (process.env.PLAYWRIGHT_E2E_IS_OWNER || '').toLowerCase() === 'true'

const nonOwnerUsername = process.env.PLAYWRIGHT_E2E_NONOWNER_USERNAME
const nonOwnerPassword = process.env.PLAYWRIGHT_E2E_NONOWNER_PASSWORD

test.describe('secure item deletion (UI)', () => {
	test.skip(
		!username || !password || !secureLibraryId,
		'Missing PLAYWRIGHT_E2E_USERNAME, PLAYWRIGHT_E2E_PASSWORD, or PLAYWRIGHT_SECURE_LIBRARY_ID',
	)

	async function login(
		page: Parameters<(typeof test)['extend']>[0]['page'],
		creds: { username: string; password: string },
	) {
		await page.goto('/')
		await page.getByLabel(/username/i).fill(creds.username)
		await page.getByLabel(/password/i).fill(creds.password)
		await page.getByRole('button', { name: /log\s*in/i }).click()
		await expect(page).not.toHaveURL(/\/auth/i)
	}

	async function openSecureLibraryBooks(page: Parameters<(typeof test)['extend']>[0]['page']) {
		await page.goto(`/libraries/${secureLibraryId}/books`)
		await expect(page).toHaveURL(new RegExp(`/libraries/${secureLibraryId}/books`))
	}

	async function openSecureLibrarySeries(page: Parameters<(typeof test)['extend']>[0]['page']) {
		await page.goto(`/libraries/${secureLibraryId}/series`)
		await expect(page).toHaveURL(new RegExp(`/libraries/${secureLibraryId}/series`))
	}

	async function unlockIfNeeded(
		page: Parameters<(typeof test)['extend']>[0]['page'],
		accountPassword?: string,
	) {
		const overlayTitle = page.getByText('Unlock secure library')
		const images = page.locator('[data-testid="entity-card-image"]')

		await Promise.race([
			overlayTitle.waitFor({ state: 'visible', timeout: 15000 }),
			images.first().waitFor({ state: 'visible', timeout: 15000 }),
		]).catch(() => {})

		const overlayVisible = await overlayTitle.isVisible().catch(() => false)
		if (!overlayVisible) return

		const passwordInput = page.getByRole('textbox', { name: /account password/i })
		const passwordInputVisible = await passwordInput.isVisible().catch(() => false)
		if (!passwordInputVisible) {
			await expect(overlayTitle).not.toBeVisible({ timeout: 30000 })
			return
		}

		await passwordInput.fill(accountPassword || '')

		const unlockButton = page.getByRole('button', { name: /^Unlock$/i })
		await unlockButton.click()

		const unlocked = await overlayTitle
			.waitFor({ state: 'hidden', timeout: 8000 })
			.then(() => true)
			.catch(() => false)
		if (unlocked) return

		const advancedButton = page.getByRole('button', { name: /^Advanced$/i })
		const advancedVisible = await advancedButton.isVisible().catch(() => false)
		if (advancedVisible) {
			await advancedButton.click()
		}

		const restoreButton = page.getByRole('button', { name: /restore keypair/i })
		const restoreVisible = await restoreButton.isVisible().catch(() => false)
		if (restoreVisible) {
			await restoreButton.click()
			const restored = await overlayTitle
				.waitFor({ state: 'hidden', timeout: 8000 })
				.then(() => true)
				.catch(() => false)
			if (restored) return
		}

		const generateButton = page.getByRole('button', { name: /generate new keypair/i })
		const generateVisible = await generateButton.isVisible().catch(() => false)
		if (generateVisible) {
			await generateButton.click()
			await expect(overlayTitle).not.toBeVisible({ timeout: 30000 })
			return
		}

		await expect(overlayTitle).not.toBeVisible({ timeout: 30000 })
	}

	test('owner: delete book sends X-LMK header and refetches catalog', async ({ page }) => {
		test.skip(!isOwner, 'Missing PLAYWRIGHT_E2E_IS_OWNER=true')

		await login(page, { username: username || '', password: password || '' })
		await openSecureLibraryBooks(page)
		await unlockIfNeeded(page, password)

		let deleteHeaders: Record<string, string> | null = null
		let catalogFetches = 0

		page.on('request', (req) => {
			if (
				req.method() === 'GET' &&
				req.url().includes(`/secure/libraries/${secureLibraryId}/catalog`)
			) {
				catalogFetches += 1
			}
		})

		await page.route(`**/secure/libraries/${secureLibraryId}/media/*`, async (route) => {
			deleteHeaders = route.request().headers()
			await route.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify({ deleted_ids: ['stub'], series_auto_deleted: [] }),
			})
		})

		const baselineCatalogFetches = catalogFetches

		const menu = page.locator('[data-testid^="secure-book-menu-"]').first()
		await expect(menu).toBeVisible({ timeout: 30000 })
		await menu.click()

		await page
			.getByText(/^Delete$/)
			.first()
			.click()
		await page.getByRole('button', { name: /^Delete$/i }).click()

		await expect.poll(() => (deleteHeaders ? true : false), { timeout: 10000 }).toBe(true)
		expect(deleteHeaders?.['x-lmk']).toBeTruthy()

		await expect
			.poll(() => catalogFetches, { timeout: 15000 })
			.toBeGreaterThanOrEqual(baselineCatalogFetches + 1)
	})

	test('owner: delete series confirmation shows media count and sends X-LMK', async ({ page }) => {
		test.skip(!isOwner, 'Missing PLAYWRIGHT_E2E_IS_OWNER=true')

		await login(page, { username: username || '', password: password || '' })
		await openSecureLibrarySeries(page)
		await unlockIfNeeded(page, password)

		let deleteHeaders: Record<string, string> | null = null
		await page.route(`**/secure/libraries/${secureLibraryId}/series/*`, async (route) => {
			deleteHeaders = route.request().headers()
			await route.fulfill({
				status: 200,
				contentType: 'application/json',
				body: JSON.stringify({ deleted_ids: ['stub'], media_count: 1 }),
			})
		})

		const menu = page.locator('[data-testid^="secure-series-menu-"]').first()
		await expect(menu).toBeVisible({ timeout: 30000 })
		await menu.click()

		await page
			.getByText(/^Delete$/)
			.first()
			.click()

		await expect(page.getByText(/will delete\s+\d+\s+book/i)).toBeVisible({ timeout: 15000 })
		await page.getByRole('button', { name: /^Delete$/i }).click()

		await expect.poll(() => (deleteHeaders ? true : false), { timeout: 10000 }).toBe(true)
		expect(deleteHeaders?.['x-lmk']).toBeTruthy()
	})

	test('non-owner: delete menu not visible', async ({ page }) => {
		test.skip(
			!nonOwnerUsername || !nonOwnerPassword,
			'Missing PLAYWRIGHT_E2E_NONOWNER_USERNAME and PLAYWRIGHT_E2E_NONOWNER_PASSWORD',
		)

		await login(page, { username: nonOwnerUsername || '', password: nonOwnerPassword || '' })
		await openSecureLibraryBooks(page)
		await unlockIfNeeded(page, nonOwnerPassword)

		await expect(page.locator('[data-testid^="secure-book-menu-"]')).toHaveCount(0)
	})
})
