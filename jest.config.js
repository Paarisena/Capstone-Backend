export default {
  testEnvironment: 'node',
  setupFilesAfterEnv: ['./tests/setup.js'],
  collectCoverageFrom: [
    '**/*.js',
    '!node_modules/**',
    '!tests/**',
    '!jest.config.js'
  ],
  testMatch: [
    '<rootDir>/tests/**/*.test.js',
    '<rootDir>/**/*.test.js'
  ],
  transform: {
    '^.+\\.js$': 'babel-jest'
  },
  moduleFileExtensions: ['js', 'json'],
  verbose: true
};