/* Parser-only source inspection; imports are never resolved or evaluated. */
const fs = require('node:fs');
const ts = require(process.argv[2]);
const files = process.argv.slice(3);
const findings = [];
let parseErrors = 0;
for (const file of files) {
  const tree = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
  parseErrors += tree.parseDiagnostics.length;
  const aliases = new Map();
  function register(node) {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier) && ['child_process','node:child_process'].includes(node.moduleSpecifier.text)) {
      const bindings = node.importClause?.namedBindings;
      if (bindings && ts.isNamespaceImport(bindings)) aliases.set(bindings.name.text, 'child_process');
      if (node.importClause?.name) aliases.set(node.importClause.name.text, 'child_process');
      if (bindings && ts.isNamedImports(bindings)) for (const element of bindings.elements) aliases.set(element.name.text, 'child_process.'+(element.propertyName || element.name).text);
    }
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isCallExpression(node.initializer) && node.initializer.expression.getText(tree) === 'require' && node.initializer.arguments.length === 1 && ts.isStringLiteral(node.initializer.arguments[0]) && ['child_process','node:child_process'].includes(node.initializer.arguments[0].text)) {
      if (ts.isIdentifier(node.name)) aliases.set(node.name.text, 'child_process');
      if (ts.isObjectBindingPattern(node.name)) for (const element of node.name.elements) aliases.set(element.name.getText(tree), 'child_process.'+(element.propertyName || element.name).getText(tree));
    }
    ts.forEachChild(node, register);
  }
  register(tree);
  function visit(node) {
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      let name = node.expression.getText(tree);
      if (ts.isPropertyAccessExpression(node.expression) && ts.isCallExpression(node.expression.expression)) {
        const receiver = node.expression.expression;
        if (receiver.expression.getText(tree) === 'require' && receiver.arguments.length === 1 && ts.isStringLiteral(receiver.arguments[0]) && ['child_process','node:child_process'].includes(receiver.arguments[0].text)) name = 'child_process.'+node.expression.name.text;
      }
      const parts = name.split('.');
      if (aliases.has(parts[0])) name = [aliases.get(parts[0]), ...parts.slice(1)].join('.');
      let rule = null, severity = 'high';
      if (name === 'eval' || name === 'globalThis.eval') rule = 'javascript.eval';
      else if (name === 'Function' || name === 'globalThis.Function') rule = 'javascript.function-constructor';
      else if (['setTimeout','setInterval'].includes(name) && node.arguments?.length && (ts.isStringLiteral(node.arguments[0]) || ts.isNoSubstitutionTemplateLiteral(node.arguments[0]))) rule = 'javascript.string-timer';
      else if (['child_process.exec','child_process.execSync'].includes(name)) rule = 'javascript.shell-execution';
      else if (['child_process.spawn','child_process.spawnSync','child_process.execFile','child_process.execFileSync','child_process.fork'].includes(name)) {
        rule = 'javascript.process-call'; severity = 'info';
        for (const arg of node.arguments || []) if (ts.isObjectLiteralExpression(arg)) {
          for (const option of arg.properties) if (ts.isPropertyAssignment(option) && option.name.getText(tree) === 'shell' && option.initializer.kind !== ts.SyntaxKind.FalseKeyword) {rule = 'javascript.shell-execution'; severity = 'high';}
        }
      }
      if (rule) {
        const location = tree.getLineAndCharacterOfPosition(node.getStart(tree));
        findings.push({path: file, line: location.line+1, column: location.character+1, rule, severity});
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(tree);
}
console.log(JSON.stringify({files, findings, parse_errors: parseErrors}));
