import { expect, test } from '@playwright/test'

const username = process.env.PLAYWRIGHT_E2E_USERNAME
const password = process.env.PLAYWRIGHT_E2E_PASSWORD
const secureLibraryId = process.env.PLAYWRIGHT_SECURE_LIBRARY_ID
const secureOnlySearch = process.env.PLAYWRIGHT_SECURE_ONLY_SEARCH

test.describe('secure library unlock + browse', () => {
	test.skip(
		!username || !password || !secureLibraryId,
		'Missing PLAYWRIGHT_E2E_USERNAME, PLAYWRIGHT_E2E_PASSWORD, or PLAYWRIGHT_SECURE_LIBRARY_ID',
	)

	async function login(page: Parameters<(typeof test)['extend']>[0]['page']) {
		await page.goto('/')
		// LoginOrClaimScene uses labeled inputs for username and password
		await page.getByLabel(/username/i).fill(username || '')
		await page.getByLabel(/password/i).fill(password || '')
		// The login button label is i18n'd; commonly "Login" (no space)
		await page.getByRole('button', { name: /log\s*in/i }).click()
		// Wait for navigation away from auth screen
		await expect(page).not.toHaveURL(/\/auth/i)
	}

	async function openSecureLibraryBooks(page: Parameters<(typeof test)['extend']>[0]['page']) {
		await page.goto(`/libraries/${secureLibraryId}/books`)
		await expect(page).toHaveURL(new RegExp(`/libraries/${secureLibraryId}/books`))
	}

	async function unlockIfNeeded(page: Parameters<(typeof test)['extend']>[0]['page']) {
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

		await passwordInput.fill(password || '')

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

	async function assertHasBookCards(page: Parameters<(typeof test)['extend']>[0]['page']) {
		const emptyState = page.getByText("It doesn't look like there are any books here")
		const noMatch = page.getByText('No books match your search')
		const secureNotEncrypted = page.getByText('Secure library has not been encrypted yet')
		const secureEmptyOrNotScanned = page.getByText('Secure library is empty or not yet scanned')
		const secureBroken = page.getByText('Secure library is currently broken')
		const secureError = page.getByText('Secure library error')
		const overlayTitle = page.getByText('Unlock secure library')

		const images = page.locator('[data-testid="entity-card-image"]')

		await Promise.race([
			images.first().waitFor({ state: 'visible', timeout: 30000 }),
			overlayTitle.waitFor({ state: 'visible', timeout: 30000 }),
		]).catch(() => {})

		const hasCards = await images
			.first()
			.isVisible()
			.catch(() => false)
		if (hasCards) return

		const isLocked = await overlayTitle.isVisible().catch(() => false)
		if (isLocked) {
			await unlockIfNeeded(page)
			await images
				.first()
				.waitFor({ state: 'visible', timeout: 30000 })
				.catch(() => {})
			const nowHasCards = await images
				.first()
				.isVisible()
				.catch(() => false)
			if (nowHasCards) return
			throw new Error(
				'Precondition failed: secure library is still locked (Unlock secure library overlay is visible).',
			)
		}

		const isEmpty = await emptyState.isVisible().catch(() => false)
		const isNoMatch = await noMatch.isVisible().catch(() => false)
		const isSecureNotEncrypted = await secureNotEncrypted.isVisible().catch(() => false)
		const isSecureEmptyOrNotScanned = await secureEmptyOrNotScanned.isVisible().catch(() => false)
		const isSecureBroken = await secureBroken.isVisible().catch(() => false)
		const isSecureError = await secureError.isVisible().catch(() => false)

		if (isEmpty || isNoMatch) {
			throw new Error(
				'Precondition failed: books grid is empty (no book cards rendered). Ensure the secure library has at least one supported book and the secure scan completed successfully.',
			)
		}
		if (isSecureNotEncrypted || isSecureEmptyOrNotScanned || isSecureBroken || isSecureError) {
			throw new Error(
				'Precondition failed: secure library is not ready (not encrypted / not scanned / broken). Ensure the secure library is ENCRYPTED and has at least one supported book.',
			)
		}
		throw new Error(
			'Precondition failed: expected secure book cards, but none were rendered and no known empty/locked state was detected.',
		)
	}

	async function logout(page: Parameters<(typeof test)['extend']>[0]['page']) {
		const signOutIcon = page.getByLabel('Sign Out')
		const signOutIconVisible = await signOutIcon.isVisible().catch(() => false)
		if (signOutIconVisible) {
			await signOutIcon.click()
		} else {
			// Most browser layouts render the sidebar UserMenu which includes the username text.
			const sidebarUser = page.getByText(username || '', { exact: true }).first()
			const sidebarUserVisible = await sidebarUser.isVisible().catch(() => false)
			if (sidebarUserVisible) {
				await sidebarUser.click()
			}

			const logoutButton = page.getByRole('button', { name: /^Logout$/i })
			const signOutButton = page.getByRole('button', { name: /^Sign out$/i })
			const logoutVisible = await logoutButton.isVisible().catch(() => false)
			if (logoutVisible) {
				await logoutButton.click()
			} else {
				await signOutButton.click()
			}
		}

		const dialog = page.getByRole('dialog')
		const dialogVisible = await dialog.isVisible().catch(() => false)
		if (dialogVisible) {
			await dialog.getByRole('button', { name: /^Sign out$/i }).click()
		}

		await expect(page).toHaveURL(/\/auth/i)
	}

	test('secure library appears locked after login (unlock overlay shown)', async ({
		page,
	}) => {
		await login(page)
		await openSecureLibraryBooks(page)
		await expect(page.getByText('Unlock secure library')).toBeVisible()
	})

	test('unlocks configured secure library and catalog appears (Books view usable)', async ({
		page,
	}) => {
		await login(page)
		await openSecureLibraryBooks(page)
		await unlockIfNeeded(page)
		await expect(page.getByText('Unlock secure library')).not.toBeVisible()
		await expect(page.getByRole('link', { name: /^Books$/i })).toBeVisible()
	})

	test('unlock → browse → thumbnails render (blob URLs)', async ({ page }) => {
		await login(page)
		await openSecureLibraryBooks(page)
		await unlockIfNeeded(page)
		await assertHasBookCards(page)

		const thumbs = page.locator('[data-testid="entity-card-image"]')
		try {
			await expect
				.poll(
					async () => {
						const count = await thumbs.count()
						for (let i = 0; i < Math.min(count, 8); i++) {
							const src = await thumbs.nth(i).getAttribute('src')
							if (src && src.startsWith('blob:')) return true
						}
						return false
					},
					{ timeout: 30000 },
				)
				.toBe(true)
		} catch {
			throw new Error(
				'Precondition failed: no secure book thumbnails resolved to blob: URLs. Ensure at least one secure book has a generated encrypted thumbnail (e.g., a CBZ with images; PDFs require a working PDFium install on the server).',
			)
		}
	})

	test('full journey: unlock → open book overview → read → reader overlay appears → close', async ({
		page,
	}) => {
		await login(page)
		await openSecureLibraryBooks(page)
		await unlockIfNeeded(page)
		await assertHasBookCards(page)

		const thumbs = page.locator('[data-testid="entity-card-image"]')
		const backLink = page.getByTitle('Go to media overview')
		const readButton = page.getByRole('button', { name: /^Read$/i })
		const count = await thumbs.count()
		const maxToTry = Math.min(count, 6)
		let opened = false
		for (let i = 0; i < maxToTry; i++) {
			await thumbs.nth(i).click()
			const dialog = await page.waitForEvent('dialog', { timeout: 1500 }).catch(() => null)
			if (dialog) {
				await dialog.accept()
				continue
			}
			// Now we should be on the book overview page - click Read to open reader
			const readVisible = await readButton
				.waitFor({ state: 'visible', timeout: 10000 })
				.then(() => true)
				.catch(() => false)
			if (!readVisible) {
				// If Read button not visible, go back and try next book
				await page.goBack()
				continue
			}
			await readButton.click()
			const readerVisible = await backLink
				.waitFor({ state: 'visible', timeout: 60000 })
				.then(() => true)
				.catch(() => false)
			if (readerVisible) {
				opened = true
				break
			}
		}

		if (!opened) {
			throw new Error(
				'Precondition failed: could not open secure reader overlay for any of the first books. The secure reader currently only supports CBZ (zip) with images; add a CBZ to the secure library and re-run the secure scan.',
			)
		}

		// Click on the page to show the toolbar (hidden by default)
		await page.click('body')
		await backLink.waitFor({ state: 'visible', timeout: 5000 })
		await backLink.click()
		await expect(readButton).toBeVisible()
	})

	test('logout clears crypto material (requires unlock again on next login)', async ({
		page,
	}) => {
		await login(page)
		await openSecureLibraryBooks(page)
		await unlockIfNeeded(page)
		await logout(page)

		await login(page)
		await openSecureLibraryBooks(page)
		await expect(page.getByText('Unlock secure library')).toBeVisible()
	})

	test('global search excludes secure results', async ({ page }) => {
		test.skip(!secureOnlySearch, 'Missing PLAYWRIGHT_SECURE_ONLY_SEARCH')
		await login(page)

		await page.goto('/books')
		const input = page.getByPlaceholder('Search')
		await input.fill(secureOnlySearch || '')

		// Search input is debounced; wait for URL to reflect the filter.
		await expect(page).toHaveURL(/search=/)

		await expect(page.getByText('No books match your search')).toBeVisible({ timeout: 30000 })
	})

	test('revocation (404) shows access revoked message and blocks unlock', async ({ page }) => {
		await login(page)
		await openSecureLibraryBooks(page)
		await unlockIfNeeded(page)
		await expect(page.getByText('Unlock secure library')).not.toBeVisible()

		await page.route(`**/secure/libraries/${secureLibraryId}/access-status`, (route) =>
			route.fulfill({ status: 404, body: '' }),
		)
		await page.goto('/')
		await openSecureLibraryBooks(page)

		await expect(page.getByText('Unlock secure library')).not.toBeVisible({ timeout: 15000 })
		await expect(
			page
				.locator('#main')
				.getByText('Access to this secure library has been revoked or is not available.'),
		).toBeVisible({ timeout: 15000 })
	})

	test('reader cache reuse (reopen same book does not refetch encrypted file)', async ({
		page,
	}) => {
		await login(page)
		await openSecureLibraryBooks(page)
		await unlockIfNeeded(page)
		await assertHasBookCards(page)

		const fileUrlPattern = new RegExp(`/secure/libraries/${secureLibraryId}/media/[^/]+/file`)
		let fileFetchCount = 0
		page.on('request', (req) => {
			if (req.method() === 'GET' && fileUrlPattern.test(req.url())) {
				fileFetchCount += 1
			}
		})

		const thumbs = page.locator('[data-testid="entity-card-image"]')
		const backLink = page.getByTitle('Go to media overview')
		const readButton = page.getByRole('button', { name: /^Read$/i })
		const count = await thumbs.count()
		const maxToTry = Math.min(count, 6)
		let openedIndex = -1

		for (let i = 0; i < maxToTry; i++) {
			await thumbs.nth(i).click()
			const dialog = await page.waitForEvent('dialog', { timeout: 1500 }).catch(() => null)
			if (dialog) {
				await dialog.accept()
				continue
			}
			// Now on book overview page - click Read to open reader
			const readVisible = await readButton
				.waitFor({ state: 'visible', timeout: 10000 })
				.then(() => true)
				.catch(() => false)
			if (!readVisible) {
				await page.goBack()
				continue
			}
			await readButton.click()
			const readerVisible = await backLink
				.waitFor({ state: 'visible', timeout: 60000 })
				.then(() => true)
				.catch(() => false)
			if (readerVisible) {
				openedIndex = i
				break
			}
		}

		if (openedIndex < 0) {
			throw new Error(
				'Precondition failed: could not open secure reader overlay for any of the first books. The secure reader currently only supports CBZ (zip) with images; add a CBZ to the secure library and re-run the secure scan.',
			)
		}

		const afterFirstOpen = fileFetchCount
		expect(afterFirstOpen).toBeGreaterThan(0)
		// Click on the page to show the toolbar (hidden by default)
		await page.click('body')
		await backLink.waitFor({ state: 'visible', timeout: 5000 })
		await backLink.click()
		await expect(readButton).toBeVisible()

		// Re-open the same book via Read button (should use cached pages)
		await readButton.click()
		// Wait for reader to load, then show toolbar
		await page.waitForTimeout(2000)
		await page.click('body')
		await backLink.waitFor({ state: 'visible', timeout: 5000 })
		expect(fileFetchCount).toBe(afterFirstOpen)
		await backLink.click()
	})

	test('keep-alive pings while reader is open (accelerated interval)', async ({ page }) => {
		await page.addInitScript(() => {
			const originalSetInterval = window.setInterval
			window.setInterval = ((fn: TimerHandler, timeout?: number, ...args: any[]) => {
				if (timeout === 5 * 60 * 1000) {
					return originalSetInterval(fn, 100, ...args)
				}
				return originalSetInterval(fn, timeout, ...args)
			}) as any
		})

		let heartbeatCount = 0
		page.on('request', (req) => {
			if (req.method() === 'POST' && req.url().includes('/session/heartbeat')) {
				heartbeatCount += 1
			}
		})

		await login(page)
		await openSecureLibraryBooks(page)
		await unlockIfNeeded(page)
		await assertHasBookCards(page)

		const thumbs = page.locator('[data-testid="entity-card-image"]')
		const backLink = page.getByTitle('Go to media overview')
		const readButton = page.getByRole('button', { name: /^Read$/i })
		await thumbs.first().click()
		await readButton.waitFor({ state: 'visible', timeout: 10000 })
		await readButton.click()
		// Wait for reader to load, then show toolbar to verify we're in reader
		await page.waitForTimeout(2000)
		await page.click('body')
		await backLink.waitFor({ state: 'visible', timeout: 5000 })
		const baseline = heartbeatCount
		await expect.poll(() => heartbeatCount, { timeout: 15000 }).toBeGreaterThan(baseline + 1)
		// Toolbar may have auto-hidden, show it again before clicking back
		// ReaderHeader is position:fixed with y:-100% animation, use JS click
		await page.keyboard.press('Space')
		await backLink.waitFor({ state: 'visible', timeout: 5000 })
		await page.waitForTimeout(300) // Wait for framer-motion animation (0.2s)
		await backLink.evaluate((el: HTMLElement) => el.click())
	})

	test('tab hidden → visible within grace window triggers keep-alive ping', async ({
		page,
	}) => {
		await page.addInitScript(() => {
			const originalNow = Date.now
			let offset = 0
			Date.now = () => originalNow() + offset
			;(window as any).__advanceNow = (ms: number) => {
				offset += ms
			}
		})

		let heartbeatCount = 0
		page.on('request', (req) => {
			if (req.method() === 'POST' && req.url().includes('/session/heartbeat')) {
				heartbeatCount += 1
			}
		})

		await login(page)
		await openSecureLibraryBooks(page)
		await unlockIfNeeded(page)
		await assertHasBookCards(page)
		const thumbs = page.locator('[data-testid="entity-card-image"]')
		const backLink = page.getByTitle('Go to media overview')
		const readButton = page.getByRole('button', { name: /^Read$/i })
		await thumbs.first().click()
		await readButton.waitFor({ state: 'visible', timeout: 10000 })
		await readButton.click()
		// Wait for reader to load, then show toolbar
		await page.waitForTimeout(2000)
		await page.click('body')
		await backLink.waitFor({ state: 'visible', timeout: 5000 })
		const baseline = heartbeatCount

		const otherTab = await page.context().newPage()
		await otherTab.goto('about:blank')
		await otherTab.bringToFront()
		await page.waitForTimeout(250)
		await page.evaluate(() => (window as any).__advanceNow(10 * 60 * 1000))
		await page.bringToFront()
		await page.evaluate(() => {
			window.dispatchEvent(new Event('focus'))
			document.dispatchEvent(new Event('visibilitychange'))
		})
		await otherTab.close()

		await expect.poll(() => heartbeatCount, { timeout: 10000 }).toBeGreaterThan(baseline)
	})

	test('session expiry shows restore modal; password-only re-auth restores in-place', async ({
		page,
	}) => {
		await login(page)
		await openSecureLibraryBooks(page)
		await unlockIfNeeded(page)

		let forced = false
		await page.route('**/api/v1/**', (route) => {
			const url = route.request().url()
			if (!forced && url.includes('/api/v1/media')) {
				forced = true
				return route.fulfill({ status: 401, body: '{}' })
			}
			return route.continue()
		})
		await page.goto('/books')
		await expect(page.getByText(/session expired/i)).toBeVisible({ timeout: 15000 })
		await page.getByLabel(/^Password$/i).fill(password || '')
		await page.getByRole('button', { name: /re-authenticate/i }).click()
		await expect(page.getByText(/session expired/i)).not.toBeVisible({ timeout: 30000 })
	})
})
