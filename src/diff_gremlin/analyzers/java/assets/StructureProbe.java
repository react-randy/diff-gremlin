/* Shipped parser-only driver. It never resolves dependencies or executes source. */
import com.sun.source.tree.*;
import com.sun.source.util.*;
import javax.tools.*;
import java.nio.file.*;
import java.util.*;

public final class StructureProbe {
    private static String quote(String value) {
        return "\""+value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")+"\"";
    }
    private static final class Scan extends TreeScanner<Void, Void> {
        int types = 0, methods = 0;
        final CompilationUnitTree unit;
        final SourcePositions positions;
        final List<String> findings;
        Scan(CompilationUnitTree unit, SourcePositions positions, List<String> findings) {
            this.unit = unit; this.positions = positions; this.findings = findings;
        }
        private void finding(Tree node, String rule, String severity) {
            long offset = positions.getStartPosition(unit, node);
            if (offset < 0) return;
            findings.add("{\"path\":"+quote(Paths.get(unit.getSourceFile().toUri()).toAbsolutePath().toString())+
                ",\"line\":"+unit.getLineMap().getLineNumber(offset)+",\"column\":"+unit.getLineMap().getColumnNumber(offset)+
                ",\"rule\":"+quote(rule)+",\"severity\":"+quote(severity)+"}");
        }
        private List<String> commandParts(List<? extends ExpressionTree> arguments) {
            if (arguments.isEmpty()) return List.of();
            ExpressionTree first = arguments.get(0);
            if (first instanceof NewArrayTree array) {
                return literalParts(array.getInitializers());
            }
            List<String> values = literalParts(arguments);
            if (values.size() == 1) return Arrays.asList(values.get(0).split("\\s+"));
            return values;
        }
        private List<String> literalParts(List<? extends ExpressionTree> expressions) {
            if (expressions == null) return List.of();
            List<String> values = new ArrayList<>();
            for (ExpressionTree expression: expressions) {
                if (!(expression instanceof LiteralTree literal) || !(literal.getValue() instanceof String value)) break;
                values.add(value);
            }
            return values;
        }
        private boolean explicitShell(List<? extends ExpressionTree> arguments) {
            List<String> values = commandParts(arguments);
            if (values.size() < 2) return false;
            String executable = values.get(0).replace('\\', '/');
            String name = executable.substring(executable.lastIndexOf('/') + 1).toLowerCase(Locale.ROOT);
            return Set.of("sh", "bash", "zsh", "dash", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh").contains(name)
                && Set.of("-c", "/c", "-command").contains(values.get(1).toLowerCase(Locale.ROOT));
        }
        private void processFinding(Tree node, List<? extends ExpressionTree> arguments, String rule) {
            if (explicitShell(arguments)) finding(node, "java.shell-execution", "high");
            else finding(node, rule, "info");
        }
        @Override public Void visitClass(ClassTree tree, Void unused) { types++; return super.visitClass(tree, unused); }
        @Override public Void visitMethod(MethodTree tree, Void unused) { methods++; return super.visitMethod(tree, unused); }
        @Override public Void visitMethodInvocation(MethodInvocationTree tree, Void unused) {
            String select = tree.getMethodSelect().toString().replace(" ", "");
            if (select.equals("Runtime.getRuntime().exec")) processFinding(tree, tree.getArguments(), "java.runtime-exec");
            else if (select.equals("System.exit")) finding(tree, "java.system-exit", "low");
            else if (select.equals("Class.forName")) finding(tree, "java.reflective-load", "low");
            else if (select.endsWith(".setAccessible")) finding(tree, "java.reflective-access", "low");
            else if (select.equals("Unsafe.getUnsafe") || select.equals("sun.misc.Unsafe.getUnsafe")) finding(tree, "java.unsafe-api", "low");
            else if (select.endsWith(".getEngineByName")) finding(tree, "java.script-engine", "low");
            else if (select.equals("engine.eval")) finding(tree, "java.script-eval", "high");
            return super.visitMethodInvocation(tree, unused);
        }
        @Override public Void visitNewClass(NewClassTree tree, Void unused) {
            String name = tree.getIdentifier().toString();
            if (name.equals("ProcessBuilder") || name.equals("java.lang.ProcessBuilder")) processFinding(tree, tree.getArguments(), "java.process-builder");
            return super.visitNewClass(tree, unused);
        }
    }
    public static void main(String[] paths) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("JDK parser unavailable");
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        List<String> findings = new ArrayList<>();
        List<String> files = new ArrayList<>();
        int types = 0, methods = 0;
        try (StandardJavaFileManager manager = compiler.getStandardFileManager(diagnostics, Locale.ROOT, java.nio.charset.StandardCharsets.UTF_8)) {
            JavacTask task = (JavacTask)compiler.getTask(null, manager, diagnostics,
                List.of("-proc:none", "-implicit:none", "-encoding", "UTF-8"), null, manager.getJavaFileObjects(paths));
            Iterable<? extends CompilationUnitTree> units = task.parse();
            SourcePositions positions = Trees.instance(task).getSourcePositions();
            for (CompilationUnitTree unit: units) {
                files.add(quote(Paths.get(unit.getSourceFile().toUri()).toAbsolutePath().toString()));
                Scan scan = new Scan(unit, positions, findings); scan.scan(unit, null);
                types += scan.types; methods += scan.methods;
            }
        }
        int errors = 0;
        for (Diagnostic<? extends JavaFileObject> diagnostic: diagnostics.getDiagnostics()) {
            if (diagnostic.getKind() != Diagnostic.Kind.ERROR) continue;
            errors++;
            if (diagnostic.getSource() == null) continue;
            findings.add("{\"path\":"+quote(Paths.get(diagnostic.getSource().toUri()).toAbsolutePath().toString())+
                ",\"line\":"+Math.max(1,diagnostic.getLineNumber())+",\"column\":"+Math.max(1,diagnostic.getColumnNumber())+
                ",\"rule\":\"java.syntax\",\"severity\":\"medium\"}");
        }
        System.out.println("{\"files\":["+String.join(",",files)+"],\"findings\":["+String.join(",",findings)+
            "],\"type_count\":"+types+",\"method_count\":"+methods+",\"error_count\":"+errors+"}");
    }
}
