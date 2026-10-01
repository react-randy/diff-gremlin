/* Single-file lexical binding inspection; target imports/configs are never loaded. */
const fs = require('node:fs');
const ts = require(process.argv[2]);
const files = process.argv.slice(3);
const findings = [];
let parseErrors = 0;
const globals = new Set(['eval', 'Function', 'setTimeout', 'setInterval', 'globalThis', 'require']);
function isolatedChecker(file, tree) {
  const host = {
    getSourceFile: name => name === file ? tree : undefined,
    getDefaultLibFileName: () => '', writeFile() {}, getCurrentDirectory: () => '',
    getDirectories: () => [], fileExists: name => name === file,
    readFile: () => undefined, getCanonicalFileName: name => name,
    useCaseSensitiveFileNames: () => true, getNewLine: () => '\n'
  };
  return ts.createProgram([file], {noResolve: true, noLib: true, allowJs: true}, host).getTypeChecker();
}
function childProcessLiteral(node) {
  return node && ts.isStringLiteral(node) && ['child_process', 'node:child_process'].includes(node.text);
}
function propertyName(node) {
  return ts.isIdentifier(node) || ts.isStringLiteral(node) ? node.text : '';
}
function importSpecifierAlias(declaration) {
  const clause = declaration.parent.parent;
  if (clause.isTypeOnly || declaration.isTypeOnly || !childProcessLiteral(clause.parent.moduleSpecifier)) return '';
  return 'child_process.' + (declaration.propertyName || declaration.name).text;
}
function importAlias(declaration) {
  if (ts.isImportSpecifier(declaration)) {
    return importSpecifierAlias(declaration);
  }
  if (ts.isNamespaceImport(declaration)) return importAlias(declaration.parent);
  if (ts.isImportClause(declaration) && !declaration.isTypeOnly && childProcessLiteral(declaration.parent.moduleSpecifier)) return 'child_process';
  return '';
}
function importEqualsAlias(declaration) {
  const reference = declaration.moduleReference;
  if (declaration.isTypeOnly || !ts.isExternalModuleReference(reference)) return '';
  return childProcessLiteral(reference.expression) ? 'child_process' : '';
}
function requireCall(node, context) {
  if (!ts.isCallExpression(node) || node.arguments.length !== 1) return false;
  return expressionName(node.expression, context) === 'require' && childProcessLiteral(node.arguments[0]);
}
function bindingElementAlias(declaration, context) {
  const owner = declaration.parent.parent;
  if (!ts.isObjectBindingPattern(declaration.parent) || !owner.initializer || declaration.dotDotDotToken) return '';
  const base = expressionName(owner.initializer, context);
  return base ? base + '.' + propertyName(declaration.propertyName || declaration.name) : '';
}
function declarationAlias(declaration, context) {
  if (!declaration) return '';
  const imported = importAlias(declaration);
  if (imported) return imported;
  if (ts.isImportEqualsDeclaration(declaration)) return importEqualsAlias(declaration);
  if (ts.isVariableDeclaration(declaration) && declaration.initializer) return expressionName(declaration.initializer, context);
  if (ts.isBindingElement(declaration)) return bindingElementAlias(declaration, context);
  return '';
}
function identifierName(node, context) {
  const symbol = context.checker.getSymbolAtLocation(node);
  if (!symbol || !symbol.declarations?.length) return globals.has(node.text) ? node.text : '';
  if (context.bindings.has(symbol)) return context.bindings.get(symbol);
  if (context.resolving.has(symbol)) return '';
  context.resolving.add(symbol);
  const name = declarationAlias(symbol.valueDeclaration || symbol.declarations?.[0], context);
  context.resolving.delete(symbol);
  return name;
}
function memberExpressionName(node, context) {
  if (ts.isPropertyAccessExpression(node)) {
    const base = expressionName(node.expression, context);
    return base ? base + '.' + node.name.text : '';
  }
  if (ts.isElementAccessExpression(node) && ts.isStringLiteral(node.argumentExpression)) {
    const base = expressionName(node.expression, context);
    return base ? base + '.' + node.argumentExpression.text : '';
  }
  return '';
}
function transparentExpression(node) {
  return ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node);
}
function expressionName(node, context) {
  if (!node) return '';
  if (ts.isIdentifier(node)) return identifierName(node, context);
  if (transparentExpression(node)) return expressionName(node.expression, context);
  if (ts.isCallExpression(node)) return requireCall(node, context) ? 'child_process' : '';
  return memberExpressionName(node, context);
}
function bindPattern(pattern, name, context) {
  if (ts.isIdentifier(pattern)) {
    const symbol = context.checker.getSymbolAtLocation(pattern);
    if (symbol) context.bindings.set(symbol, name);
  } else if (ts.isObjectBindingPattern(pattern)) {
    for (const element of pattern.elements) {
      const key = propertyName(element.propertyName || element.name);
      bindPattern(element.name, name && key && !element.dotDotDotToken ? name + '.' + key : '', context);
    }
  } else if (ts.isObjectLiteralExpression(pattern)) {
    bindObjectAssignment(pattern, name, context);
  }
}
function bindObjectAssignment(pattern, name, context) {
  for (const member of pattern.properties) {
    if (ts.isPropertyAssignment(member)) {
      const key = propertyName(member.name);
      bindPattern(member.initializer, name && key ? name + '.' + key : '', context);
    }
    if (ts.isShorthandPropertyAssignment(member)) {
      // Shorthand assignment identifiers need the value symbol, not the property symbol.
      const symbol = context.checker.getShorthandAssignmentValueSymbol(member);
      if (symbol) context.bindings.set(symbol, name ? name + '.' + member.name.text : '');
    }
  }
}
function updateBinding(node, context) {
  if (ts.isVariableDeclaration(node)) bindPattern(node.name, expressionName(node.initializer, context), context);
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) bindPattern(node.left, expressionName(node.right, context), context);
}
function shellProperty(option) {
  return ts.isPropertyAssignment(option) && propertyName(option.name) === 'shell' && option.initializer.kind !== ts.SyntaxKind.FalseKeyword;
}
function shellOption(args) {
  return args.some(arg => ts.isObjectLiteralExpression(arg) && arg.properties.some(shellProperty));
}
function stringTimer(node, name) {
  if (!['setTimeout', 'setInterval', 'globalThis.setTimeout', 'globalThis.setInterval'].includes(name) || !node.arguments?.length) return false;
  return ts.isStringLiteral(node.arguments[0]) || ts.isNoSubstitutionTemplateLiteral(node.arguments[0]);
}
function callRule(node, name) {
  if (['eval', 'globalThis.eval'].includes(name)) return ['javascript.eval', 'high'];
  if (['Function', 'globalThis.Function'].includes(name)) return ['javascript.function-constructor', 'high'];
  if (stringTimer(node, name)) return ['javascript.string-timer', 'high'];
  if (['child_process.exec', 'child_process.execSync'].includes(name)) return ['javascript.shell-execution', 'high'];
  if (['child_process.spawn', 'child_process.spawnSync', 'child_process.execFile', 'child_process.execFileSync', 'child_process.fork'].includes(name)) {
    return shellOption(node.arguments || []) ? ['javascript.shell-execution', 'high'] : ['javascript.process-call', 'info'];
  }
  return null;
}
function observeCall(node, context) {
  const observation = callRule(node, expressionName(node.expression, context));
  if (!observation) return;
  const [rule, severity] = observation;
  const location = context.tree.getLineAndCharacterOfPosition(node.getStart(context.tree));
  findings.push({path: context.file, line: location.line + 1, column: location.character + 1, rule, severity});
}
function visitCalls(node, context) {
  // An uncalled function's writes cannot change another lexical owner's observations.
  const nested = ts.isFunctionLike(node) ? {...context, bindings: new Map(context.bindings)} : context;
  if (ts.isCallExpression(node) || ts.isNewExpression(node)) observeCall(node, nested);
  ts.forEachChild(node, child => visitCalls(child, nested));
  updateBinding(node, nested);
}
for (const file of files) {
  const tree = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
  parseErrors += tree.parseDiagnostics.length;
  visitCalls(tree, {file, tree, checker: isolatedChecker(file, tree), bindings: new Map(), resolving: new Set()});
}
console.log(JSON.stringify({files, findings, parse_errors: parseErrors}));
