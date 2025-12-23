import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
	testDir: './tests/playwright',
	timeout: 60000,
	workers: process.env.PLAYWRIGHT_WORKERS
		? Number.parseInt(process.env.PLAYWRIGHT_WORKERS, 10)
		: 1,
	expect: {
		timeout: 5000,
	},
	use: {
		baseURL: process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:10801',
		trace: 'on-first-retry',
	},
	projects: [
		{
			name: 'chromium',
			use: { ...devices['Desktop Chrome'] },
		},
	],
})
