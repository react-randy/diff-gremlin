/* Native ESLint classic complexity, with a separate code-path coverage counter. */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const [eslintPath, parserPath, ...files] = process.argv.slice(2);
const {ESLint} = require(eslintPath);
const parser = require(path.join(parserPath, 'dist', 'index.js'));
const astUtils = require(path.join(eslintPath, 'lib', 'rules', 'utils', 'ast-utils.js'));
const functions = [];
let expectedCount = 0;
let parseErrors = 0;
const observedOrigins = new Set(['function', 'class-field-initializer', 'class-static-block']);
let identities = new Map();
const bodyIdentities = new WeakMap();
function digest(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function keyName(node) {
  if (!node || node.computed) return '';
  const key = node.key;
  if (!key) return '';
  if (key.type === 'Identifier' || key.type === 'PrivateIdentifier') return key.name;
  // Source literal values remain private; their digest is enough for identity.
  return '#key:' + digest(String(key.value));
}
function binding(node) {
  if (node.id && node.id.type === 'Identifier') return node.id.name;
  const parent = node.parent;
  if (!parent) return '';
  if (parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier') return parent.id.name;
  if ((parent.type === 'Property' || parent.type === 'MethodDefinition' || parent.type === 'PropertyDefinition') && parent.value === node) {
    const key = keyName(parent);
    return key ? (parent.static ? 'static:' : '') + (parent.kind || 'value') + ':' + key : '';
  }
  return '';
}
function bodyIdentity(node, sourceCode) {
  if (!bodyIdentities.has(node)) bodyIdentities.set(node,
    digest(JSON.stringify(sourceCode.getTokens(node).map(token => [token.type, token.value]))));
  return bodyIdentities.get(node);
}
function stableIdentity(node, kind, sourceCode) {
  const parts = [];
  for (let current = node; current; current = current.parent) {
    if (current === node || /^(?:Function|ArrowFunction|Class|Object)(?:Declaration|Expression)$/.test(current.type)) {
      const named = binding(current);
      parts.push(named || 'anonymous:' + bodyIdentity(current, sourceCode));
    }
  }
  const symbol = parts.reverse().join('.') + (kind === 'function' ? '' : ':' + kind);
  if (!symbol || symbol.length > 2048) throw new Error('Function identity exceeds bound');
  return {symbol, identity: digest(kind + '\0' + symbol),
    identity_kind: parts.some(part => part.startsWith('anonymous:')) ? 'body' : 'qualified'};
}
const coverage = {meta: {schema: []}, create(context) {
  const sourceCode = context.sourceCode;
  return {onCodePathStart(codePath, node) {
    if (!observedOrigins.has(codePath.origin)) return;
    expectedCount++;
    const loc = codePath.origin === 'function' ? astUtils.getFunctionHeadLoc(node, sourceCode) :
      codePath.origin === 'class-static-block' ? sourceCode.getFirstToken(node).loc : node.loc;
    const key = loc.start.line + ':' + (loc.start.column + 1) + ':' + codePath.origin;
    if (identities.has(key)) throw new Error('Duplicate code-path location');
    identities.set(key, stableIdentity(node, codePath.origin, sourceCode));
  }};
}};
function observation(message, file) {
  if (message.ruleId !== 'complexity' || message.messageId !== 'complex') throw new Error('Unexpected complexity diagnostic');
  const match = / has a complexity of (\d+)\. Maximum allowed is 0\.$/.exec(message.message);
  if (!match) throw new Error('Unexpected native complexity schema');
  const kind = message.message.startsWith('Class field initializer') ? 'class-field-initializer' :
    message.message.startsWith('Class static block') ? 'class-static-block' : 'function';
  const key = message.line + ':' + message.column + ':' + kind;
  const identity = identities.get(key);
  if (!identity) throw new Error('Complexity diagnostic lacks structural identity');
  identities.delete(key);
  return {path: file, line: message.line, column: message.column, cc: Number(match[1]), kind, ...identity};
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
    identities = new Map();
    const virtual = path.join(process.cwd(), 'input' + observedFiles.length + path.extname(file));
    const rows = await eslint.lintText(fs.readFileSync(file, 'utf8'), {filePath: virtual});
    if (rows.length !== 1) throw new Error('Unexpected ESLint result count');
    observedFiles.push(file);
    for (const message of rows[0].messages) {
      if (message.fatal) parseErrors++;
      else functions.push(observation(message, file));
    }
    if (!parseErrors && identities.size) throw new Error('Unobserved function identity');
  }
  console.log(JSON.stringify({files: observedFiles, findings: [], functions, expected_count: expectedCount, parse_errors: parseErrors}));
})().catch(() => {console.error('Controlled ESLint complexity failed'); process.exitCode = 2;});
