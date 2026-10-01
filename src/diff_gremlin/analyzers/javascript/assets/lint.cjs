/* Controlled ESLint flat configuration. Target configs and plugins are never loaded. */
const {createRequire} = require('node:module');
const fs = require('node:fs');
const path = require('node:path');
const [eslintPath, parserPath, pluginPath, globalsPath, ...files] = process.argv.slice(2);
const {ESLint} = require(eslintPath);
const parser = require(path.join(parserPath, 'dist', 'index.js'));
const plugin = require(path.join(pluginPath, 'dist', 'index.js'));
const globals = require(globalsPath);
const inherited = {
  'no-unused-vars': 'off', '@typescript-eslint/no-unused-vars': 'error',
  '@typescript-eslint/no-explicit-any': 'error', '@typescript-eslint/explicit-function-return-type': 'off',
  '@typescript-eslint/no-inferrable-types': 'off', 'no-console': 'off', eqeqeq: 'error',
  'no-var': 'error', 'prefer-const': 'error', 'no-throw-literal': 'error', 'no-shadow': 'off',
  '@typescript-eslint/no-shadow': 'error', 'no-duplicate-imports': 'error', 'no-self-assign': 'error',
  'no-self-compare': 'error', 'no-unreachable': 'error', 'no-constant-condition': 'error',
  'no-dupe-args': 'error', 'no-dupe-keys': 'error', 'no-empty': 'error', 'no-extra-semi': 'error',
  'no-func-assign': 'error', 'no-import-assign': 'error', 'no-irregular-whitespace': 'error',
  'no-loss-of-precision': 'error', 'no-sparse-arrays': 'error', 'no-unexpected-multiline': 'error',
  'no-unsafe-negation': 'error', 'use-isnan': 'error', 'valid-typeof': 'error', 'no-fallthrough': 'error',
  'no-global-assign': 'error', 'no-redeclare': 'off', '@typescript-eslint/no-redeclare': 'error',
  'no-unused-labels': 'error', 'no-useless-escape': 'error', 'no-undef': 'off', 'constructor-super': 'error',
  'no-const-assign': 'error', 'no-dupe-class-members': 'off', '@typescript-eslint/no-dupe-class-members': 'error',
  'no-new-symbol': 'error', 'no-this-before-super': 'error'
};
(async () => {
  const installedRequire = createRequire(path.join(eslintPath, 'package.json'));
  const recommended = installedRequire('@eslint/js').configs.recommended.rules;
  const javascriptRules = Object.fromEntries(Object.entries(inherited).filter(([name]) => !name.startsWith('@typescript-eslint/')));
  Object.assign(javascriptRules, {'no-unused-vars': 'error', 'no-shadow': 'error', 'no-redeclare': 'error', 'no-dupe-class-members': 'error'});
  const eslint = new ESLint({cwd: process.cwd(), overrideConfigFile: true, ignore: false, allowInlineConfig: false,
    overrideConfig: [{files: ['**/*.{js,jsx,mjs,cjs,ts,tsx,mts,cts}'],
      languageOptions: {parser, ecmaVersion: 'latest', sourceType: 'module',
        globals: {...globals.es2022, ...globals.node, ...globals.browser},
        parserOptions: {ecmaFeatures: {jsx: true}, project: false}},
      plugins: {'@typescript-eslint': plugin},
      rules: {...recommended, ...javascriptRules}},
      {files: ['**/*.{ts,tsx,mts,cts}'], rules: {...plugin.configs.recommended.rules, ...inherited}},
      {files: ['**/*.{cjs,cts}'], languageOptions: {sourceType: 'commonjs'}}]});
  // lintText prevents relative-path ignore/config search and uses only owned configuration.
  const results = [];
  for (const file of files) {
    const virtual = path.join(process.cwd(), 'input'+results.length+path.extname(file));
    const rows = await eslint.lintText(fs.readFileSync(file, 'utf8'), {filePath: virtual});
    rows.forEach(row => { row.filePath = file; });
    results.push(...rows);
  }
  const findings = results.flatMap(r => r.messages.map(m => ({path: r.filePath,
    line: m.line || 1, column: m.column || 1, rule: m.ruleId || 'syntax',
    severity: m.severity === 2 ? 'medium' : 'low'})));
  console.log(JSON.stringify({files: results.map(r => r.filePath), findings,
    error_count: results.reduce((n,r) => n+r.errorCount,0),
    warning_count: results.reduce((n,r) => n+r.warningCount,0),
    fatal_count: results.reduce((n,r) => n+r.fatalErrorCount,0)}));
})().catch(() => { console.error('Controlled ESLint analysis failed'); process.exitCode = 2; });
