import type { Config } from 'jest'

export default {
	moduleNameMapper: {
		'^@/(.*)$': '<rootDir>/src/$1',
		'\\.(css|less|sass|scss)$': '<rootDir>/jest.styleMock.ts',
		'^react-markdown$': '<rootDir>/jest.componentMock.tsx',
		'^remark-directive$': '<rootDir>/jest.moduleMock.ts',
		'^remark-directive-rehype$': '<rootDir>/jest.moduleMock.ts',
		'^@noble/ciphers/chacha\\.js$': '<rootDir>/jest.nobleMock.ts',
		'^@noble/curves/ed25519\\.js$': '<rootDir>/jest.nobleMock.ts',
	},
	setupFilesAfterEnv: ['<rootDir>/jest.setup.ts'],
	modulePathIgnorePatterns: ['<rootDir>/dist/'],
	testEnvironment: 'jsdom',
	transform: {
		'^.+\\.tsx?$': 'babel-jest',
	},
} satisfies Config
