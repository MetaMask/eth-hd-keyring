module.exports = {
  collectCoverage: true,
  coverageReporters: ['text', 'html'],
  coverageThreshold: {
    global: {
      branches: 84,
      functions: 100,
      lines: 96,
      statements: 96,
    },
  },
  moduleFileExtensions: ['js', 'json', 'jsx', 'ts', 'tsx', 'node'],
  // "resetMocks" resets all mocks, including mocked modules, to jest.fn(),
  // between each test case.
  resetMocks: true,
  // "restoreMocks" restores all mocks created using jest.spyOn to their
  // original implementations, between each test. It does not affect mocked
  // modules.
  restoreMocks: true,
  testEnvironment: 'node',
  testMatch: ['**/test/**/*.js'],
  testTimeout: 2500,
};
