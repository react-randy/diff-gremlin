/* TypeScript compiler API: no tsconfig, plugins, emit, or project scripts. */
const ts = require(process.argv[2]);
const files = process.argv.slice(3);
const options = {noEmit: true, strict: true, skipLibCheck: false, types: [],
  target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.NodeNext,
  moduleResolution: ts.ModuleResolutionKind.NodeNext, jsx: ts.JsxEmit.Preserve,
  noResolve: true, allowJs: false, incremental: false};
const program = ts.createProgram(files, options);
const diagnostics = ts.getPreEmitDiagnostics(program);
const findings = diagnostics.filter(d => d.file && files.includes(d.file.fileName)).map(d => {
  const location = d.file.getLineAndCharacterOfPosition(d.start || 0);
  return {path: d.file.fileName, line: location.line+1, column: location.character+1,
    rule: 'TS'+d.code, severity: d.category === ts.DiagnosticCategory.Error ? 'medium' : 'low'};
});
const dependencyCodes = new Set([2307, 2688, 2792, 7016, 6059, 6307]);
console.log(JSON.stringify({files, findings,
  error_count: diagnostics.filter(d => d.category === ts.DiagnosticCategory.Error).length,
  warning_count: diagnostics.filter(d => d.category === ts.DiagnosticCategory.Warning).length,
  global_count: diagnostics.filter(d => !d.file || !files.includes(d.file.fileName)).length,
  dependency_count: diagnostics.filter(d => dependencyCodes.has(d.code)).length}));
