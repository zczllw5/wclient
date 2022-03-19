module.exports = {
    extends: 'lighthouse:default',
    settings: {
      audits: [
        'first-meaningful-paint',
        'speed-index',
        'interactive',
      ],
    },
  };