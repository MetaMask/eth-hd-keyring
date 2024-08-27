module.exports = {
  root: true,

  extends: ['@metamask/eslint-config', '@metamask/eslint-config-nodejs'],

  overrides: [
    {
      files: ['test/**/*.js'],
      extends: ['@metamask/eslint-config-jest'],
      rules: {
        'node/no-unpublished-require': 0,
      },
    },
  ],

  ignorePatterns: ['!.eslintrc.js', '!.prettierrc.js'],
};
