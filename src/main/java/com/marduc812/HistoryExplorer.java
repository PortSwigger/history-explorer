package com.marduc812;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.*;
import burp.api.montoya.scope.Scope;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ForkJoinPool;
import java.util.function.BooleanSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class HistoryExplorer {

    /**
     * Four threads was the pool the extension always allocated, which is fine on a
     * workstation and fatal on the 2-4 vCPU VDI a lot of testers actually run Burp
     * on: a pathological regex then pins every core the box has and the remote
     * display stack starves, so the whole machine looks hung rather than just the
     * search. Leave a core for the rest of the world; keep 4 as the ceiling so
     * behaviour on a big machine is unchanged.
     */
    private static final int SEARCH_THREADS =
            Math.max(1, Math.min(4, Runtime.getRuntime().availableProcessors() - 1));

    /** How many charAt calls pass between stop-flag polls inside a running match. */
    private static final int CANCEL_POLL_INTERVAL = 4096;

    /** Below this a pre-screen literal filters too little to pay for its own scan. */
    private static final int MIN_PRESCREEN_LITERAL = 3;

    static Logging logging;
    HistoryExplorerGui gui;
    static Scope scope;
    // Written on the EDT by the constructor and read by shutdownNow() on whatever
    // thread Burp unloads the extension from, so it cannot be a plain field.
    private volatile ExecutorService executorService;
    private volatile boolean stopSearchFlag;

    /**
     * Set when the extension is unloading, as distinct from the user pressing Stop. Burp
     * invalidates the objects behind the Montoya API once the unloading handler returns,
     * and every call on them then throws NullPointerException from inside Burp's own
     * proxy. So past this point the search must not log, must not read another message
     * and must not publish results: a user Stop still does all three, an unload does none.
     */
    private volatile boolean unloaded;

    public HistoryExplorer(MontoyaApi api, HistoryExplorerGui gui, String searchTerm, boolean regExSearch, boolean inScopeSearch ,boolean[] searchStatusCodes, boolean showProtocol, boolean showPort, String includedExtensionsString, String excludedExtensionsString, List<Boolean> httpOptions) {

        logging = api.logging();
        scope = api.scope();
        this.gui = gui;

        if (searchTerm == null || searchTerm.isEmpty()) {
            logging.logToOutput("Empty search string");
            gui.searchFinished();
            return;
        }

        // all request filters are disabled
        if (noneSelected(searchStatusCodes)) {
            logging.logToOutput("At least one of the Request Response options should be enabled");
            gui.searchFinished();
            return;
        }

        boolean searchRequests = httpOptions.get(0);
        boolean searchResponses = httpOptions.get(1);
        if (!searchRequests && !searchResponses) {
            // Both reqSearch and resSearch are false
            logging.logToOutput("At least one of the HTTP options should be enabled");
            gui.searchFinished();
            return;
        }

        // Only treat the term as a regex when the user asked for one. Compiling a
        // literal term both throws on ordinary input such as "?" or "cache[" and
        // changes what matches: the regex a+b does not match the text "a+b".
        Pattern pattern = null;
        if (regExSearch) {
            try {
                pattern = Pattern.compile(searchTerm);
            } catch (PatternSyntaxException e) {
                logging.logToError("Invalid regular expression: " + e.getMessage());
                gui.searchFinished();
                return;
            }
        }

        Set<String> includedExtensions = parseExtensions(includedExtensionsString);
        Set<String> excludedExtensions = parseExtensions(excludedExtensionsString);
        Pattern searchPattern = pattern;

        // Derived once per search, not per message: it is a property of the pattern.
        String prescreenLiteral = searchPattern == null ? null : requiredLiteral(searchTerm);
        if (prescreenLiteral != null) {
            logging.logToOutput("Pre-screening bodies on the required literal: " + prescreenLiteral);
        }

        this.executorService = Executors.newSingleThreadExecutor();
        executorService.submit(() -> {
            try {
                FilterHTTPResults filterHTTP = new FilterHTTPResults(searchRequests, searchStatusCodes, scope, inScopeSearch, includedExtensions, excludedExtensions, this::isStopped);
                processHttpHistory(api, gui, searchTerm, searchPattern, prescreenLiteral, showProtocol, showPort, searchRequests, searchResponses, filterHTTP);
            } catch (Throwable t) {
                // submit() parks throwables in a Future nobody reads, so without this
                // the search dies leaving no trace and the button stuck on "Stop".
                // A cancelled search is exempt: shutdownNow() interrupts this thread on
                // purpose, and the InterruptedException that ends the wait in
                // processHttpHistory is that cancellation working, not a fault.
                if (!stopSearchFlag) {
                    logging.logToError("Search failed: " + t);
                }
            } finally {
                gui.searchFinished();
            }
        });

        // Lets the queued task finish, then reaps the thread. Without it every search
        // leaks a live non-daemon thread for the rest of the Burp session.
        executorService.shutdown();
    }

    public void stopSearch() {
        stopSearchFlag = true;
    }

    /**
     * Cancels the search on extension unload, where there is no Stop button left to press
     * because the tab has gone. Without it the search outlives the extension: the executor
     * thread is non-daemon and the parallel pass holds SEARCH_THREADS cores, so a
     * pathological regex keeps burning them for the rest of the Burp session.
     *
     * The flag is what actually ends the search -- nothing on the search path tests the
     * interrupt status -- and shutdownNow() is here to unpark the thread waiting on the
     * parallel pass in processHttpHistory rather than let it sit there until that drains.
     */
    public void shutdownNow() {

        // Before the flag that ends the search, so no thread it releases can get as far
        // as an API call believing the extension is still loaded.
        unloaded = true;
        stopSearch();

        ExecutorService executor = executorService;
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    private boolean isStopped() {
        return stopSearchFlag;
    }

    private void processHttpHistory(MontoyaApi api, HistoryExplorerGui gui, String searchTerm, Pattern pattern, String requiredLiteral, boolean showProtocol, boolean showPort, boolean searchRequests, boolean searchResponses, FilterHTTPResults filterHTTP) throws Exception {

        List<ProxyHttpRequestResponse> httpHistory = api.proxy().history(filterHTTP);

        // An unload during the walk leaves nothing here that is safe to call -- logging
        // the count alone is an API call, and it throws.
        if (unloaded) {
            return;
        }

        Map<String, Set<String>> hostToServersMap = new ConcurrentHashMap<>();

        logging.logToOutput("#############\nRecords returned: " + httpHistory.size() + "\n##########\n");

        // Scanning message bodies is the expensive half of a search and each item is
        // independent, so fan it out. A private pool rather than the common
        // ForkJoinPool, which is shared with the rest of Burp.
        ForkJoinPool searchPool = new ForkJoinPool(SEARCH_THREADS);
        try {
            searchPool.submit(() -> httpHistory.parallelStream().forEach(item -> {

                if (stopSearchFlag) {
                    return;
                }

                try {
                    HttpRequest request = item.finalRequest();
                    if (request == null) {
                        return;
                    }

                    Set<String> matchingValues = collectMatches(item, request, searchTerm, pattern, requiredLiteral, searchRequests, searchResponses, this::isStopped);
                    if (matchingValues.isEmpty()) {
                        return;
                    }

                    String hostString = buildHostLabel(request, showProtocol, showPort);
                    hostToServersMap.computeIfAbsent(hostString, key -> ConcurrentHashMap.newKeySet()).addAll(matchingValues);
                } catch (RuntimeException e) {
                    // An unload can land between the flag check above and any of the calls
                    // below it, and every one of them is an API call that then throws.
                    // Swallowed only once the search is stopping, so a genuine fault in a
                    // live search still tears the pass down and is reported.
                    if (!stopSearchFlag) {
                        throw e;
                    }
                }
            })).get();
        } finally {
            searchPool.shutdown();
        }

        // Checked again: the unload may have arrived while the pass was draining. There
        // is no tab left to publish to and no API left to log with.
        if (unloaded) {
            return;
        }

        if (stopSearchFlag) {
            logging.logToOutput("Search stopped by user.");
        }

        // Sorted because the parallel pass leaves no meaningful encounter order.
        Map<String, List<String>> newData = new LinkedHashMap<>();
        List<String> hosts = new ArrayList<>(hostToServersMap.keySet());
        Collections.sort(hosts);

        for (String host : hosts) {
            List<String> parsedValues = new ArrayList<>(hostToServersMap.get(host));
            Collections.sort(parsedValues);
            newData.put(host, parsedValues);
        }

        java.awt.EventQueue.invokeLater(() -> gui.updateResults(newData));
    }

    private static Set<String> collectMatches(ProxyHttpRequestResponse item, HttpRequest request, String searchTerm, Pattern pattern, String requiredLiteral, boolean searchRequests, boolean searchResponses, BooleanSupplier stopped) {

        Set<String> matchingValues = new LinkedHashSet<>();

        try {
            // The request is usually far smaller than the response, so scan it first.
            if (searchRequests) {
                addMatches(request.toString(), searchTerm, pattern, requiredLiteral, matchingValues, stopped);
            }

            // A literal search can only ever yield the search term, so once the request
            // has produced it there is nothing the response could add and it never has to
            // be stringified. A regex search has to scan both for their distinct matches.
            boolean nothingLeftToFind = pattern == null && !matchingValues.isEmpty();

            if (searchResponses && !nothingLeftToFind) {
                HttpResponse response = item.originalResponse();
                if (response != null) {
                    addMatches(response.toString(), searchTerm, pattern, requiredLiteral, matchingValues, stopped);
                }
            }
        } catch (SearchCancelled cancelled) {
            // Caught per item so it stays local: letting it escape would tear down the
            // whole parallel pass and surface as "Search failed". Whatever this item had
            // already matched is kept, which is how a stopped search has always behaved.
        }

        return matchingValues;
    }

    private static void addMatches(String text, String searchTerm, Pattern pattern, String requiredLiteral, Set<String> into, BooleanSupplier stopped) {

        // A literal search has nothing to extract: the matched text is the term.
        // contains() is linear and needs no cancellation hook.
        if (pattern == null) {
            if (text.contains(searchTerm)) {
                into.add(searchTerm);
            }
            return;
        }

        // find() is a single uninterruptible call, and a backtracking regex can spend
        // minutes inside one of them on a large body -- polling the stop flag only
        // between items leaves Stop dead for that whole time. Feeding the matcher a
        // CharSequence that checks the flag as it is read makes the match itself
        // cancellable, since charAt is the engine's inner loop.
        // One linear scan for a substring every match must contain. This is the whole
        // difference between a search that finishes and one that hangs the machine: on
        // 200 bodies that lack the term, pre-screening took 36 ms against more than ten
        // minutes of backtracking without it.
        if (requiredLiteral != null && !text.contains(requiredLiteral)) {
            return;
        }

        Matcher matcher = pattern.matcher(new CancellableCharSequence(text, stopped));
        while (matcher.find()) {
            into.add(matcher.group());
        }
    }

    /**
     * Finds a substring that every possible match of {@code regex} must contain, so a
     * body can be dismissed with one linear {@code indexOf} instead of a full
     * backtracking sweep. Returns null when no such substring can be established.
     *
     * This is what makes an expensive regex survivable. java.util.regex only exploits a
     * literal at the *start* of a pattern (it compiles that to a Boyer-Moore skip scan);
     * a required literal sitting anywhere else buys nothing, so a pattern like
     * "\S+eclntjsfserver/.*?" brute-forces every body in the history. Measured on a
     * 200KB minified body: 0 ms when the literal leads, 17.4 s when it does not.
     *
     * The one invariant that matters: whatever is returned MUST appear in every match.
     * Returning too little only costs speed; returning too much silently loses hits, so
     * every construct whose necessity cannot be established locally ends the current run
     * and anything ambiguous about the pattern as a whole bails out entirely.
     */
    static String requiredLiteral(String regex) {

        // Alternation means no single literal is common to all matches. Inline flags
        // such as (?i) and (?x) change what the literals even mean -- (?i) would make
        // contains() case-sensitive against a case-insensitive pattern. \Q..\E can put a
        // quantifier on a quoted char (\Qab\E? requires only "a"), which would make the
        // scan below over-extract. None of these are worth parsing precisely.
        if (regex.indexOf('|') >= 0 || regex.contains("(?") || regex.contains("\\Q")) {
            return null;
        }

        String best = "";
        StringBuilder run = new StringBuilder();
        int groupDepth = 0;

        for (int i = 0; i < regex.length(); i++) {

            char c = regex.charAt(i);
            int literal = -1;

            if (c == '\\') {
                if (i + 1 >= regex.length()) {
                    break;
                }
                literal = literalOfEscape(regex.charAt(++i));
            } else if (c == '(') {
                groupDepth++;
            } else if (c == ')') {
                groupDepth = Math.max(0, groupDepth - 1);
            } else if (c == '[') {
                i = endOfCharacterClass(regex, i);
            } else if (c == '{') {
                // Skip the bound itself: the digits and comma in a{0,3} are not text,
                // and reading them as literals would demand "0,3" of every body.
                int close = regex.indexOf('}', i);
                i = close < 0 ? regex.length() - 1 : close;
            } else if (".^$*+?}]".indexOf(c) < 0) {
                literal = c;
            }

            // A literal inside a group may be made optional by a quantifier on the group,
            // which is not visible from here, so only depth 0 counts.
            if (literal < 0 || groupDepth > 0) {
                best = longer(best, run);
                run.setLength(0);
                continue;
            }

            // A quantifier that permits zero occurrences makes this char optional. '+'
            // requires at least one, so it stays. '{' is not worth parsing: treat any
            // bound as possibly zero.
            char next = i + 1 < regex.length() ? regex.charAt(i + 1) : 0;
            if (next == '?' || next == '*' || next == '{') {
                best = longer(best, run);
                run.setLength(0);
                continue;
            }

            run.append((char) literal);
        }

        best = longer(best, run);
        return best.length() >= MIN_PRESCREEN_LITERAL ? best : null;
    }

    private static String longer(String best, CharSequence candidate) {
        return candidate.length() > best.length() ? candidate.toString() : best;
    }

    /** The literal character an escape stands for, or -1 if it is a class or reference. */
    private static int literalOfEscape(char escaped) {

        switch (escaped) {
            case 'n': return '\n';
            case 'r': return '\r';
            case 't': return '\t';
            case 'f': return '\f';
            default:
                // Escaped punctuation stands for itself. Anything alphanumeric is a
                // class (\d \w \S), a boundary (\b), a reference (\1) or an escape
                // taking arguments (\p, \x, unicode) -- none of them a fixed character.
                return Character.isLetterOrDigit(escaped) ? -1 : escaped;
        }
    }

    /** Index of the ']' closing the class opened at {@code open}, or the last index. */
    private static int endOfCharacterClass(String regex, int open) {

        for (int i = open + 1; i < regex.length(); i++) {
            char c = regex.charAt(i);
            if (c == '\\') {
                i++;
            } else if (c == ']' && i > open + 1) {
                return i;
            }
        }

        return regex.length() - 1;
    }

    /** Thrown out of a running match when the user presses Stop. */
    private static final class SearchCancelled extends RuntimeException {
        SearchCancelled() {
            // No message, no stack trace: this is control flow, not a fault.
            super(null, null, false, false);
        }
    }

    /**
     * Wraps the message text so a long-running match can be aborted. Single-threaded
     * by construction -- one instance is created per matcher, on the thread that runs
     * it -- so the plain int countdown needs no synchronisation.
     */
    private static final class CancellableCharSequence implements CharSequence {

        private final CharSequence delegate;
        private final BooleanSupplier stopped;
        private int countdown = CANCEL_POLL_INTERVAL;

        CancellableCharSequence(CharSequence delegate, BooleanSupplier stopped) {
            this.delegate = delegate;
            this.stopped = stopped;
        }

        @Override
        public char charAt(int index) {
            if (--countdown <= 0) {
                countdown = CANCEL_POLL_INTERVAL;
                if (stopped.getAsBoolean()) {
                    throw new SearchCancelled();
                }
            }
            return delegate.charAt(index);
        }

        @Override
        public int length() {
            return delegate.length();
        }

        @Override
        public CharSequence subSequence(int start, int end) {
            // Delegated unwrapped: this is what Matcher.group() reads, and a match that
            // already succeeded should not be cancellable while it is being extracted.
            return delegate.subSequence(start, end);
        }

        @Override
        public String toString() {
            return delegate.toString();
        }
    }

    /**
     * Builds the Host column label from the request's service rather than by parsing
     * item.url(), which reports -1 for a default port and leaves the label as
     * "://host:-1" when the URL fails to parse.
     */
    private static String buildHostLabel(HttpRequest request, boolean showProtocol, boolean showPort) {

        HttpService service = request.httpService();
        StringBuilder hostBuilder = new StringBuilder();

        if (showProtocol) {
            hostBuilder.append(service.secure() ? "https" : "http").append("://");
        }

        hostBuilder.append(service.host());

        if (showPort) {
            hostBuilder.append(':').append(service.port());
        }

        return hostBuilder.toString();
    }

    private static Set<String> parseExtensions(String extensionsString) {

        Set<String> extensions = new HashSet<>();

        if (extensionsString == null || extensionsString.trim().isEmpty()) {
            return extensions;
        }

        for (String extension : extensionsString.split(",")) {
            String trimmed = extension.trim().toLowerCase(Locale.ROOT);
            if (!trimmed.isEmpty()) {
                extensions.add(trimmed);
            }
        }

        return extensions;
    }

    private static boolean noneSelected(boolean[] statusFilter) {

        for (boolean selected : statusFilter) {
            if (selected) {
                return false;
            }
        }

        return true;
    }

    public static String getExtensionFromPath(String urlPathString) {
        try {
            // Remove query parameters if present
            int queryParamPos = urlPathString.indexOf('?');
            if (queryParamPos != -1) {
                urlPathString = urlPathString.substring(0, queryParamPos);
            }

            int lastDotPos = urlPathString.lastIndexOf('.');
            int lastSlashPos = urlPathString.lastIndexOf('/');

            // Check if the last dot comes after the last slash and is not the last character in the string
            if (lastDotPos > lastSlashPos && lastDotPos < urlPathString.length() - 1) {
                return urlPathString.substring(lastDotPos + 1);
            }
        } catch (Exception e) {
            logging.logToError("Error Parsing Extension: " + e);
        }
        return "none";
    }


}
