import java.lang.reflect.*;
import java.util.*;
import java.util.function.BooleanSupplier;
import java.util.regex.*;

/**
 * The pre-screen must never change a result set. Asserts the invariant directly
 * (every match contains the literal) and differentially (same matches with/without),
 * over curated cases plus a fuzz sweep.
 */
public class PrescreenTest {

    static Method requiredLiteral, addMatches;
    static final BooleanSupplier NEVER = () -> false;
    static int checks = 0, failures = 0, prescreened = 0;

    static String literal(String regex) throws Exception {
        return (String) requiredLiteral.invoke(null, regex);
    }

    @SuppressWarnings("unchecked")
    static Set<String> viaExtension(String text, String regex, Pattern p) throws Exception {
        Set<String> into = new LinkedHashSet<>();
        addMatches.invoke(null, text, regex, p, literal(regex), into, NEVER);
        return into;
    }

    static Set<String> viaRawRegex(String text, Pattern p) {
        Set<String> out = new LinkedHashSet<>();
        Matcher m = p.matcher(text);
        while (m.find()) out.add(m.group());
        return out;
    }

    static void check(String regex, String text) throws Exception {
        Pattern p;
        try { p = Pattern.compile(regex); } catch (PatternSyntaxException e) { return; }

        checks++;
        String lit = literal(regex);
        Set<String> expected = viaRawRegex(text, p);
        Set<String> actual = viaExtension(text, regex, p);

        if (lit != null) {
            prescreened++;
            // The load-bearing invariant: the literal must be inside EVERY match.
            for (String match : expected) {
                if (!match.contains(lit)) {
                    failures++;
                    System.out.printf("  OVER-EXTRACT regex=%s literal=%s match=%s%n",
                            regex, lit, match);
                    return;
                }
            }
        }
        if (!expected.equals(actual)) {
            failures++;
            System.out.printf("  MISMATCH regex=%s text=%s literal=%s expected=%s actual=%s%n",
                    regex, text, lit, expected, actual);
        }
    }

    public static void main(String[] args) throws Exception {
        Class<?> he = Class.forName("com.marduc812.HistoryExplorer");
        requiredLiteral = he.getDeclaredMethod("requiredLiteral", String.class);
        requiredLiteral.setAccessible(true);
        addMatches = he.getDeclaredMethod("addMatches", String.class, String.class,
                Pattern.class, String.class, Set.class, BooleanSupplier.class);
        addMatches.setAccessible(true);

        System.out.println("=== extraction on known patterns ===");
        String[][] expectLiteral = {
            {"\"\\S+eclntjsfserver/.*?\"", "eclntjsfserver/"},
            {"Server: nginx",              "Server: nginx"},
            {"(abc)?defgh",                "defgh"},
            {"abcd|efgh",                  null},   // alternation
            {"(?i)abcdef",                 null},   // inline flags
            {"\\Qabcd\\E?",                null},   // quoted + quantifier
            {"ab{0,3}cdef",                "cdef"}, // bound digits are not text
            {"colou?rsxyz",                "rsxyz"},// 'u' optional -> run breaks
            {"x*abcdef",                   "abcdef"},
            {"[0-9]{3}-abcd",              "-abcd"},
            {"\\d+\\.\\d+\\.beta",         ".beta"},// escaped dot is a literal dot
            {"a",                          null},   // below MIN_PRESCREEN_LITERAL
        };
        for (String[] c : expectLiteral) {
            String got = literal(c[0]);
            boolean ok = Objects.equals(got, c[1]);
            if (!ok) failures++;
            System.out.printf("  %s %-26s -> %s%s%n", ok ? "ok  " : "FAIL",
                    c[0], got, ok ? "" : "   (expected " + c[1] + ")");
        }

        System.out.println("=== fuzz: random patterns vs random texts ===");
        Random rnd = new Random(20260811);
        String[] atoms = {"a","b","c","ab","abc","abcd",".","[ab]","[^a]","\\d","\\w","\\S",
                          "(a)","(abc)","(ab|c)","\\.","\\-","a?","b*","c+","a{0,2}","b{2}",
                          "(abc)?","(ab)+","^","$","\\bab","x","abcde"};
        for (int i = 0; i < 300_000; i++) {
            StringBuilder sb = new StringBuilder();
            int parts = 1 + rnd.nextInt(4);
            for (int j = 0; j < parts; j++) sb.append(atoms[rnd.nextInt(atoms.length)]);
            StringBuilder t = new StringBuilder();
            int len = rnd.nextInt(14);
            for (int j = 0; j < len; j++) t.append("abcd.-x".charAt(rnd.nextInt(7)));
            check(sb.toString(), t.toString());
        }

        System.out.printf("%nchecks=%,d  pre-screened=%,d  failures=%d%n", checks, prescreened, failures);
        System.out.println(failures == 0 ? "PASS" : "FAIL");
        if (failures != 0) System.exit(1);
    }
}
