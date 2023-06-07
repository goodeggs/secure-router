module.exports = {
  presets: [
    [
      '@babel/preset-env',
      {
        targets: {
          node: '16',
          browsers: ['last 1 version', 'last 2 iOS versions'],
        },
      },
    ],
    '@babel/typescript',
  ],
};
