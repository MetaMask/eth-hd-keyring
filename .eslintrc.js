module.exports = {
  root: true,

  extends: ['@metamask/eslint-config', '@metamask/eslint-config-nodejs'],

  overrides: [
    {
      files: ['test/**/*.js'],
      extends: ['@metamask/eslint-config-mocha'],
    },
  ],

  ignorePatterns: ['!.eslintrc.js', '!.prettierrc.js'],
};
