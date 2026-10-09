/* TypeScript compiler API: no tsconfig, plugins, emit, or project scripts. */
const ts = require(process.argv[2]);
const files = process.argv.slice(3);
const options = {noEmit: true, strict: true, skipLibCheck: false, types: [],
  target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.NodeNext,
  moduleResolution: ts.ModuleResolutionKind.NodeNext, jsx: ts.JsxEmit.Preserve,
  noResolve: true, allowJs: false, incremental: false};
const program = ts.createProgram(files, options);
const diagnostics = ts.getPreEmitDiagnostics(program);
const templates = new Map(Object.values(ts.Diagnostics).map(d => [d.code, d.message]));
const primitiveTypes = new Set(['string', 'number', 'boolean', 'bigint', 'symbol', 'object',
  'any', 'unknown', 'never', 'void', 'undefined', 'null']);
const escapePattern = text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
function safeMessage(message, code) {
  const template = templates.get(code);
  if (!template) return 'Review TS'+code+' diagnostic';
  const parts = template.split(/\{\d+\}/);
  const pattern = new RegExp('^'+parts.map(escapePattern).join('([\\s\\S]*?)')+'$');
  const match = pattern.exec(message.slice(0, 4096));
  if (!match) return template.replace(/\{\d+\}/g, '[redacted]');
  return parts.map((part, index) => {
    if (index === parts.length-1) return part;
    const value = match[index+1];
    const named = /(?:[Pp]arameter|[Pp]roperty|[Nn]ame|[Nn]amespace|[Mm]ember|[Cc]lass|[Ii]nterface) '(?:[A-Za-z_$][A-Za-z0-9_$]*\.)*$/.test(part)
      && value.length <= 80 && /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$/.test(value);
    const module = /[Mm]odule '$/.test(part) && value.length <= 100
      && /^(?:@[A-Za-z0-9_-]+\/)?[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(value)
      && !value.split('/').some(segment => segment === '..');
    return part+(named || module || primitiveTypes.has(value) ? value : '[redacted]');
  }).join('');
}
function diagnosticText(d, depth = 0) {
  if (depth > 8) return '[redacted]';
  if (typeof d.messageText === 'string') return safeMessage(d.messageText, d.code);
  const chain = d.messageText;
  return [safeMessage(chain.messageText, chain.code),
    ...(chain.next || []).map(next => diagnosticText(next, depth+1))].join(' ');
}
const findings = diagnostics.filter(d => d.file && files.includes(d.file.fileName)).map(d => {
  const location = d.file.getLineAndCharacterOfPosition(d.start || 0);
  return {path: d.file.fileName, line: location.line+1, column: location.character+1,
    rule: 'TS'+d.code, severity: d.category === ts.DiagnosticCategory.Error ? 'medium' : 'low',
    message: diagnosticText(d).slice(0, 4096)};
});
const dependencyCodes = new Set([2307, 2688, 2792, 7016, 6059, 6307]);
console.log(JSON.stringify({files, findings,
  error_count: diagnostics.filter(d => d.category === ts.DiagnosticCategory.Error).length,
  warning_count: diagnostics.filter(d => d.category === ts.DiagnosticCategory.Warning).length,
  global_count: diagnostics.filter(d => !d.file || !files.includes(d.file.fileName)).length,
  dependency_count: diagnostics.filter(d => dependencyCodes.has(d.code)).length}));
