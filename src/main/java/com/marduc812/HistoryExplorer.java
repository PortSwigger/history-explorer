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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class HistoryExplorer {

    /** Matches the pool the extension has always allocated for search work. */
    private static final int SEARCH_THREADS = 4;

    static Logging logging;
    HistoryExplorerGui gui;
    static Scope scope;
    private ExecutorService executorService;
    private volatile boolean stopSearchFlag;

    public HistoryExplorer(MontoyaApi api, HistoryExplorerGui gui, String searchTerm, boolean regExSearch, boolean inScopeSearch ,boolean[] searchStatusCodes, boolean showProtocol, boolean showPort, String includedExtensionsString, String excludedExtensionsString, List<Boolean> httpOptions) {

        logging = api.logging();
        scope = api.scope();
        this.gui = gui;

        if (searchTerm == null || searchTerm.isEmpty()) {
            logging.logToOutput("Empty search string");
            gui.enableSearchButton();
            return;
        }

        // all request filters are disabled
        if (noneSelected(searchStatusCodes)) {
            logging.logToOutput("At least one of the Request Response options should be enabled");
            gui.enableSearchButton();
            return;
        }

        boolean searchRequests = httpOptions.get(0);
        boolean searchResponses = httpOptions.get(1);
        if (!searchRequests && !searchResponses) {
            // Both reqSearch and resSearch are false
            logging.logToOutput("At least one of the HTTP options should be enabled");
            gui.enableSearchButton();
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
                gui.enableSearchButton();
                return;
            }
        }

        Set<String> includedExtensions = parseExtensions(includedExtensionsString);
        Set<String> excludedExtensions = parseExtensions(excludedExtensionsString);
        Pattern searchPattern = pattern;

        this.executorService = Executors.newSingleThreadExecutor();
        executorService.submit(() -> {
            try {
                FilterHTTPResults filterHTTP = new FilterHTTPResults(searchRequests, searchStatusCodes, scope, inScopeSearch, includedExtensions, excludedExtensions, this::isStopped);
                processHttpHistory(api, gui, searchTerm, searchPattern, showProtocol, showPort, searchRequests, searchResponses, filterHTTP);
            } catch (Throwable t) {
                // submit() parks throwables in a Future nobody reads, so without this
                // the search dies leaving no trace and the button stuck on "Stop".
                logging.logToError("Search failed: " + t);
            } finally {
                gui.enableSearchButton();
            }
        });

        // Lets the queued task finish, then reaps the thread. Without it every search
        // leaks a live non-daemon thread for the rest of the Burp session.
        executorService.shutdown();
    }

    public void stopSearch() {
        stopSearchFlag = true;
    }

    private boolean isStopped() {
        return stopSearchFlag;
    }

    private void processHttpHistory(MontoyaApi api, HistoryExplorerGui gui, String searchTerm, Pattern pattern, boolean showProtocol, boolean showPort, boolean searchRequests, boolean searchResponses, FilterHTTPResults filterHTTP) throws Exception {

        List<ProxyHttpRequestResponse> httpHistory = api.proxy().history(filterHTTP);
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

                HttpRequest request = item.finalRequest();
                if (request == null) {
                    return;
                }

                Set<String> matchingValues = collectMatches(item, request, searchTerm, pattern, searchRequests, searchResponses);
                if (matchingValues.isEmpty()) {
                    return;
                }

                String hostString = buildHostLabel(request, showProtocol, showPort);
                hostToServersMap.computeIfAbsent(hostString, key -> ConcurrentHashMap.newKeySet()).addAll(matchingValues);
            })).get();
        } finally {
            searchPool.shutdown();
        }

        if (stopSearchFlag) {
            logging.logToOutput("Search stopped by user.");
        }

        // Sorted because the parallel pass leaves no meaningful encounter order.
        Map<String, String> newData = new LinkedHashMap<>();
        List<String> hosts = new ArrayList<>(hostToServersMap.keySet());
        Collections.sort(hosts);

        for (String host : hosts) {
            List<String> parsedValues = new ArrayList<>(hostToServersMap.get(host));
            Collections.sort(parsedValues);
            newData.put(host, String.join(" || ", parsedValues));
        }

        java.awt.EventQueue.invokeLater(() -> gui.updateTableData(newData));
    }

    private static Set<String> collectMatches(ProxyHttpRequestResponse item, HttpRequest request, String searchTerm, Pattern pattern, boolean searchRequests, boolean searchResponses) {

        Set<String> matchingValues = new LinkedHashSet<>();

        // The request is usually far smaller than the response, so scan it first.
        if (searchRequests) {
            addMatches(request.toString(), searchTerm, pattern, matchingValues);
        }

        // A literal search can only ever yield the search term, so once the request
        // has produced it there is nothing the response could add and it never has to
        // be stringified. A regex search has to scan both for their distinct matches.
        boolean nothingLeftToFind = pattern == null && !matchingValues.isEmpty();

        if (searchResponses && !nothingLeftToFind) {
            HttpResponse response = item.originalResponse();
            if (response != null) {
                addMatches(response.toString(), searchTerm, pattern, matchingValues);
            }
        }

        return matchingValues;
    }

    private static void addMatches(String text, String searchTerm, Pattern pattern, Set<String> into) {

        // A literal search has nothing to extract: the matched text is the term.
        if (pattern == null) {
            if (text.contains(searchTerm)) {
                into.add(searchTerm);
            }
            return;
        }

        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            into.add(matcher.group());
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
