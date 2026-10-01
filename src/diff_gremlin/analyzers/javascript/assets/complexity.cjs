/* Native ESLint classic complexity, with a separate code-path coverage counter. */
const fs = require('node:fs');
const path = require('node:path');
const [eslintPath, parserPath, ...files] = process.argv.slice(2);
const {ESLint} = require(eslintPath);
const parser = require(path.join(parserPath, 'dist', 'index.js'));
const functions = [];
let expectedCount = 0;
let parseErrors = 0;
const observedOrigins = new Set(['function', 'class-field-initializer', 'class-static-block']);
const coverage = {meta: {schema: []}, create() {
  return {onCodePathStart(codePath) {if (observedOrigins.has(codePath.origin)) expectedCount++;}};
}};
function observation(message, file) {
  if (message.ruleId !== 'complexity' || message.messageId !== 'complex') throw new Error('Unexpected complexity diagnostic');
  const match = / has a complexity of (\d+)\. Maximum allowed is 0\.$/.exec(message.message);
  if (!match) throw new Error('Unexpected native complexity schema');
  const kind = message.message.startsWith('Class field initializer') ? 'class-field-initializer' :
    message.message.startsWith('Class static block') ? 'class-static-block' : 'function';
  return {path: file, line: message.line, column: message.column, cc: Number(match[1]), kind};
}
(async () => {
  const eslint = new ESLint({cwd: process.cwd(), overrideConfigFile: true, ignore: false, allowInlineConfig: false,
    overrideConfig: [{files: ['**/*.{js,jsx,mjs,cjs,ts,tsx,mts,cts}'],
      languageOptions: {parser, ecmaVersion: 'latest', sourceType: 'module',
        parserOptions: {ecmaFeatures: {jsx: true}, project: false}},
      plugins: {coverage: {rules: {paths: coverage}}},
      rules: {complexity: ['warn', 0], 'coverage/paths': 'warn'}}]});
  const observedFiles = [];
  for (const file of files) {
    const virtual = path.join(process.cwd(), 'input' + observedFiles.length + path.extname(file));
    const rows = await eslint.lintText(fs.readFileSync(file, 'utf8'), {filePath: virtual});
    if (rows.length !== 1) throw new Error('Unexpected ESLint result count');
    observedFiles.push(file);
    for (const message of rows[0].messages) {
      if (message.fatal) parseErrors++;
      else functions.push(observation(message, file));
    }
  }
  console.log(JSON.stringify({files: observedFiles, findings: [], functions, expected_count: expectedCount, parse_errors: parseErrors}));
})().catch(() => {console.error('Controlled ESLint complexity failed'); process.exitCode = 2;});
