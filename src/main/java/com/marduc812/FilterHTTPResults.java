package com.marduc812;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scope.Scope;

import java.util.Locale;
import java.util.Set;
import java.util.function.BooleanSupplier;
import java.util.regex.Pattern;

/**
 * Pre-filter handed to api.proxy().history(...) so Burp only materialises items
 * that can contribute a result.
 *
 * The checks run cheapest first, which is the whole point of the class. Status
 * class, scope and extension are all decided from metadata; only what survives
 * them is converted to a String and scanned for the search term. That scan is by
 * far the most expensive step, because toString() materialises the entire
 * message including its body.
 */
public class FilterHTTPResults implements ProxyHistoryFilter {

    private final String searchTerm;
    private final Pattern pattern; // null when this is a literal search
    private final boolean searchRequests;
    private final boolean searchResponses;
    private final boolean[] statusClasses; // indices 0-3 = 2xx, 3xx, 4xx, 5xx
    private final Scope scope;
    private final boolean inScopeSearch;
    private final Set<String> includedExtensions;
    private final Set<String> excludedExtensions;
    private final BooleanSupplier stopped;

    public FilterHTTPResults(String searchTerm, Pattern pattern, boolean searchRequests, boolean searchResponses, boolean[] statusClasses, Scope scope, boolean inScopeSearch, Set<String> includedExtensions, Set<String> excludedExtensions, BooleanSupplier stopped) {
        this.searchTerm = searchTerm;
        this.pattern = pattern;
        this.searchRequests = searchRequests;
        this.searchResponses = searchResponses;
        this.statusClasses = statusClasses;
        this.scope = scope;
        this.inScopeSearch = inScopeSearch;
        this.includedExtensions = includedExtensions;
        this.excludedExtensions = excludedExtensions;
        this.stopped = stopped;
    }

    @Override
    public boolean matches(ProxyHttpRequestResponse requestResponse) {

        // history() scans the whole history before it returns, so without this Stop
        // does nothing for what is usually the longest part of a search.
        if (stopped.getAsBoolean()) {
            return false;
        }

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

        if (!includedExtensions.isEmpty() && !includedExtensions.contains(extension)) {
            return false;
        }

        // Everything past this point stringifies the message. The request is usually
        // far smaller than the response, so test it first and let the short circuit
        // skip stringifying the response altogether.
        if (searchRequests && contains(request.toString())) {
            return true;
        }

        return searchResponses && response != null && contains(response.toString());
    }

    private boolean statusAllowed(int statusCode) {
        int index = statusCode / 100 - 2;
        return index >= 0 && index < statusClasses.length && statusClasses[index];
    }

    private boolean contains(String text) {
        return pattern != null ? pattern.matcher(text).find() : text.contains(searchTerm);
    }
}
