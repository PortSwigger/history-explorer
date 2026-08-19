package com.marduc812;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scope.Scope;

import java.util.Locale;
import java.util.Set;
import java.util.function.BooleanSupplier;

/**
 * Pre-filter handed to api.proxy().history(...).
 *
 * It answers only from metadata — status class, scope, extension — and never
 * touches the message body. Burp calls this back on a single thread while it
 * walks the history, so anything expensive done here is work that cannot be
 * parallelised. The search term is deliberately *not* tested here; that is the
 * costly part and it belongs in the parallel pass in HistoryExplorer.
 */
public class FilterHTTPResults implements ProxyHistoryFilter {

    private final boolean searchRequests;
    private final boolean[] statusClasses; // indices 0-3 = 2xx, 3xx, 4xx, 5xx
    private final Scope scope;
    private final boolean inScopeSearch;
    private final Set<String> includedExtensions;
    private final Set<String> excludedExtensions;
    private final BooleanSupplier stopped;

    public FilterHTTPResults(boolean searchRequests, boolean[] statusClasses, Scope scope, boolean inScopeSearch, Set<String> includedExtensions, Set<String> excludedExtensions, BooleanSupplier stopped) {
        this.searchRequests = searchRequests;
        this.statusClasses = statusClasses;
        this.scope = scope;
        this.inScopeSearch = inScopeSearch;
        this.includedExtensions = includedExtensions;
        this.excludedExtensions = excludedExtensions;
        this.stopped = stopped;
    }

    @Override
    public boolean matches(ProxyHttpRequestResponse requestResponse) {

        // history() walks the whole history before it returns, so without this Stop
        // does nothing until the walk finishes.
        if (stopped.getAsBoolean()) {
            return false;
        }

        try {
            return keep(requestResponse);
        } catch (RuntimeException e) {
            // Unload can land between the check above and any call below, and Burp has
            // by then invalidated the objects they run on. Throwing here would abort
            // history() itself. Rethrown while the search is live so a real fault still
            // surfaces rather than silently dropping items from every result.
            if (!stopped.getAsBoolean()) {
                throw e;
            }
            return false;
        }
    }

    private boolean keep(ProxyHttpRequestResponse requestResponse) {

        HttpRequest request = requestResponse.finalRequest();
        if (request == null) {
            return false;
        }

        HttpResponse response = requestResponse.originalResponse();

        // A missing response leaves no status code to filter on and no body to
        // search, but the request is still searchable.
        if (response == null) {
            if (!searchRequests) {
                return false;
            }
        } else if (!statusAllowed(response.statusCode())) {
            return false;
        }

        if (inScopeSearch && !scope.isInScope(requestResponse.url())) {
            return false;
        }

        String extension = HistoryExplorer.getExtensionFromPath(requestResponse.path()).toLowerCase(Locale.ROOT);

        if (excludedExtensions.contains(extension)) {
            return false;
        }

        return includedExtensions.isEmpty() || includedExtensions.contains(extension);
    }

    private boolean statusAllowed(int statusCode) {
        int index = statusCode / 100 - 2;
        return index >= 0 && index < statusClasses.length && statusClasses[index];
    }
}
