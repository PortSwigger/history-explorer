package com.marduc812;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.regex.Pattern;

/**
 * Pre-filter handed to api.proxy().history(...) so Burp only materialises items
 * that can contribute a result.
 */
public class FilterHTTPResults implements ProxyHistoryFilter {

    private final String searchTerm;
    private final Pattern pattern; // null when this is a literal search
    private final boolean searchRequests;
    private final boolean searchResponses;

    public FilterHTTPResults(String searchTerm, Pattern pattern, boolean searchRequests, boolean searchResponses) {
        this.searchTerm = searchTerm;
        this.pattern = pattern;
        this.searchRequests = searchRequests;
        this.searchResponses = searchResponses;
    }

    @Override
    public boolean matches(ProxyHttpRequestResponse requestResponse) {
        // The request is usually far smaller than the response, so test it first and
        // let the short circuit skip stringifying the response altogether.
        if (searchRequests) {
            HttpRequest request = requestResponse.finalRequest();
            if (request != null && contains(request.toString())) {
                return true;
            }
        }

        if (searchResponses) {
            HttpResponse response = requestResponse.originalResponse();
            return response != null && contains(response.toString());
        }

        return false;
    }

    private boolean contains(String text) {
        return pattern != null ? pattern.matcher(text).find() : text.contains(searchTerm);
    }
}
