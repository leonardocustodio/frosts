import createConfig from "@frosts/eslint";

const baseConfig = createConfig("./tsconfig.json");

// Extend the test files config to add URL and fetch globals (available in Node.js 18+ and Bun)
const extendedConfig = baseConfig.map((config) => {
  if (config.files?.some?.((f) => f.includes("tests/"))) {
    return {
      ...config,
      languageOptions: {
        ...config.languageOptions,
        globals: {
          ...config.languageOptions?.globals,
          URL: "readonly",
          fetch: "readonly",
        },
      },
    };
  }
  return config;
});

export default extendedConfig;
