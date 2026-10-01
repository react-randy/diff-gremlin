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
        private List<String> builderParts(List<? extends ExpressionTree> arguments) {
            if (arguments.isEmpty()) return List.of();
            ExpressionTree first = arguments.get(0);
            if (first instanceof NewArrayTree array) {
                return literalParts(array.getInitializers());
            }
            return literalParts(arguments);
        }
        private List<String> runtimeParts(List<? extends ExpressionTree> arguments) {
            if (arguments.isEmpty()) return List.of();
            ExpressionTree first = arguments.get(0);
            if (first instanceof NewArrayTree array) return literalParts(array.getInitializers());
            if (!(first instanceof LiteralTree literal) || !(literal.getValue() instanceof String command)) return List.of();
            // Runtime.exec(String, ...) tokenizes only the command, with these JDK defaults.
            StringTokenizer tokenizer = new StringTokenizer(command);
            List<String> values = new ArrayList<>();
            while (tokenizer.hasMoreTokens()) values.add(tokenizer.nextToken());
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
        private enum OptionKind { STOP, FLAG, OPERAND, COMMAND }
        private OptionKind shortOption(String option, String name) {
            String allowed = name.equals("bash") ? "abCefhimnuvxrscokptBEHPTDlO" : "abCefhimnuvxrsco";
            String flags = option.substring(1);
            if (flags.isEmpty()) return OptionKind.STOP;
            for (int index = 0; index < flags.length(); index++) {
                if (allowed.indexOf(flags.charAt(index)) < 0) return OptionKind.STOP;
            }
            if (flags.indexOf('c') >= 0) return OptionKind.COMMAND;
            return flags.indexOf('o') >= 0 || flags.indexOf('O') >= 0 ? OptionKind.OPERAND : OptionKind.FLAG;
        }
        private OptionKind posixOption(String option, String name) {
            if (option.isEmpty() || option.equals("--") || !Set.of('-', '+').contains(option.charAt(0))) return OptionKind.STOP;
            if (!option.startsWith("--")) return shortOption(option, name);
            if (!name.equals("bash")) return OptionKind.STOP;
            if (Set.of("--rcfile", "--init-file").contains(option)) return OptionKind.OPERAND;
            return Set.of("--login", "--noediting", "--noprofile", "--norc", "--posix", "--restricted", "--verbose").contains(option)
                ? OptionKind.FLAG : OptionKind.STOP;
        }
        private OptionKind cmdOption(String option) {
            String flag = option.toLowerCase(Locale.ROOT);
            if (Set.of("/c", "/k").contains(flag)) return OptionKind.COMMAND;
            return Set.of("/d", "/s", "/q", "/a", "/u", "/e:on", "/e:off", "/f:on", "/f:off", "/v:on", "/v:off").contains(flag)
                ? OptionKind.FLAG : OptionKind.STOP;
        }
        private OptionKind powershellOption(String option) {
            String flag = option.toLowerCase(Locale.ROOT);
            if (Set.of("-c", "-command").contains(flag)) return OptionKind.COMMAND;
            if (Set.of("-executionpolicy", "-inputformat", "-outputformat", "-configurationname").contains(flag)) return OptionKind.OPERAND;
            return Set.of("-noprofile", "-noninteractive", "-nologo", "-noexit", "-sta", "-mta").contains(flag)
                ? OptionKind.FLAG : OptionKind.STOP;
        }
        private OptionKind interpreterOption(String option, String name) {
            if (Set.of("cmd", "cmd.exe").contains(name)) return cmdOption(option);
            if (Set.of("powershell", "powershell.exe", "pwsh", "pwsh.exe").contains(name)) return powershellOption(option);
            if (Set.of("sh", "bash", "zsh", "dash").contains(name)) return posixOption(option, name);
            return OptionKind.STOP;
        }
        private boolean explicitShell(List<String> values) {
            if (values.size() < 2) return false;
            String executable = values.get(0).replace('\\', '/');
            String name = executable.substring(executable.lastIndexOf('/') + 1).toLowerCase(Locale.ROOT);
            for (int index = 1; index < values.size(); index++) {
                OptionKind kind = interpreterOption(values.get(index), name);
                if (kind == OptionKind.COMMAND) return true;
                if (kind == OptionKind.STOP) return false;
                if (kind == OptionKind.OPERAND) index++;
            }
            return false;
        }
        private void processFinding(Tree node, List<String> values, String rule) {
            if (explicitShell(values)) finding(node, "java.shell-execution", "high");
            else finding(node, rule, "info");
        }
        @Override public Void visitClass(ClassTree tree, Void unused) { types++; return super.visitClass(tree, unused); }
        @Override public Void visitMethod(MethodTree tree, Void unused) { methods++; return super.visitMethod(tree, unused); }
        @Override public Void visitMethodInvocation(MethodInvocationTree tree, Void unused) {
            String select = tree.getMethodSelect().toString().replace(" ", "");
            if (select.equals("Runtime.getRuntime().exec")) processFinding(tree, runtimeParts(tree.getArguments()), "java.runtime-exec");
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
            if (name.equals("ProcessBuilder") || name.equals("java.lang.ProcessBuilder")) processFinding(tree, builderParts(tree.getArguments()), "java.process-builder");
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
