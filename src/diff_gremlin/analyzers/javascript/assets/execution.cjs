/* Parser-only source inspection; imports are never resolved or evaluated. */
const fs = require('node:fs');
const ts = require(process.argv[2]);
const files = process.argv.slice(3);
const findings = [];
let parseErrors = 0;
function childProcessLiteral(node) {
  return node && ts.isStringLiteral(node) && ['child_process', 'node:child_process'].includes(node.text);
}
function childProcessRequire(node, tree) {
  if (!node || !ts.isCallExpression(node)) return false;
  return node.expression.getText(tree) === 'require' && node.arguments.length === 1 && childProcessLiteral(node.arguments[0]);
}
function importAliases(node, aliases) {
  const clause = node.importClause;
  if (!clause) return;
  if (clause.name) aliases.set(clause.name.text, 'child_process');
  const bindings = clause.namedBindings;
  if (!bindings) return;
  if (ts.isNamespaceImport(bindings)) aliases.set(bindings.name.text, 'child_process');
  if (ts.isNamedImports(bindings)) {
    for (const element of bindings.elements) aliases.set(element.name.text, 'child_process.' + (element.propertyName || element.name).text);
  }
}
function requireAliases(node, aliases, tree) {
  if (ts.isIdentifier(node.name)) aliases.set(node.name.text, 'child_process');
  if (ts.isObjectBindingPattern(node.name)) {
    for (const element of node.name.elements) aliases.set(element.name.getText(tree), 'child_process.' + (element.propertyName || element.name).getText(tree));
  }
}
function registerAliases(node, aliases, tree) {
  if (ts.isImportDeclaration(node) && childProcessLiteral(node.moduleSpecifier)) importAliases(node, aliases);
  if (ts.isVariableDeclaration(node) && childProcessRequire(node.initializer, tree)) requireAliases(node, aliases, tree);
  ts.forEachChild(node, child => registerAliases(child, aliases, tree));
}
function callName(expression, aliases, tree) {
  let name = expression.getText(tree);
  if (ts.isPropertyAccessExpression(expression) && childProcessRequire(expression.expression, tree)) name = 'child_process.' + expression.name.text;
  const parts = name.split('.');
  if (aliases.has(parts[0])) name = [aliases.get(parts[0]), ...parts.slice(1)].join('.');
  return name;
}
function shellProperty(option, tree) {
  return ts.isPropertyAssignment(option) && option.name.getText(tree) === 'shell' && option.initializer.kind !== ts.SyntaxKind.FalseKeyword;
}
function shellOption(args, tree) {
  return args.some(arg => ts.isObjectLiteralExpression(arg) && arg.properties.some(option => shellProperty(option, tree)));
}
function stringTimer(node, name) {
  if (!['setTimeout', 'setInterval'].includes(name) || !node.arguments?.length) return false;
  return ts.isStringLiteral(node.arguments[0]) || ts.isNoSubstitutionTemplateLiteral(node.arguments[0]);
}
function callRule(node, name, tree) {
  if (['eval', 'globalThis.eval'].includes(name)) return ['javascript.eval', 'high'];
  if (['Function', 'globalThis.Function'].includes(name)) return ['javascript.function-constructor', 'high'];
  if (stringTimer(node, name)) return ['javascript.string-timer', 'high'];
  if (['child_process.exec', 'child_process.execSync'].includes(name)) return ['javascript.shell-execution', 'high'];
  if (['child_process.spawn', 'child_process.spawnSync', 'child_process.execFile', 'child_process.execFileSync', 'child_process.fork'].includes(name)) {
    return shellOption(node.arguments || [], tree) ? ['javascript.shell-execution', 'high'] : ['javascript.process-call', 'info'];
  }
  return null;
}
function visitCalls(node, aliases, tree, file) {
  if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
    const observation = callRule(node, callName(node.expression, aliases, tree), tree);
    if (observation) {
      const [rule, severity] = observation;
      const location = tree.getLineAndCharacterOfPosition(node.getStart(tree));
      findings.push({path: file, line: location.line + 1, column: location.character + 1, rule, severity});
    }
  }
  ts.forEachChild(node, child => visitCalls(child, aliases, tree, file));
}
for (const file of files) {
  const tree = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
  parseErrors += tree.parseDiagnostics.length;
  const aliases = new Map();
  registerAliases(tree, aliases, tree);
  visitCalls(tree, aliases, tree, file);
}
console.log(JSON.stringify({files, findings, parse_errors: parseErrors}));
