# Burp Suite History Explorer

This extension was developed to assist in filtering search results by host. 
During a large assessment I conducted, I wanted a clear view of which servers were operating on which software. While searching in Burp for the `Server: .*`, it returned the desired information, but I still had to sift through each request.

## Features

- Search using a literal string or a regex by selecting the `Regular expression` checkbox.
- Choose the type of `status code` to include in the history search.
- Include or exclude file extensions in your search. Use the keyword `none` for requests without an extension.
- Results are grouped per host in an expandable tree, one match per row.
- Narrow the results with the `Filter results` box without running the search again.
- Results can be copied from the right-click menu in four ways, so you get only what you asked for:
  - `Copy` (`ctrl + c`) copies the selected rows as host and value separated by a tab, so they paste straight into a spreadsheet.
  - `Copy match only` (`ctrl + shift + c`) copies just the matched values, with no host in front of them. Selecting a host copies all of its matches this way.
  - `Copy all matches for <host>` copies everything found on one host, named in the menu so you can see which. It works from a value row as well as from the host row.
  - `Copy all results` copies the whole tree.
  
  Copying always follows the `Filter results` box, so a filtered view copies only what it shows.
- Filter only for in-scope items

## Screenshot

![Searching with regex for the Server header.](./Images/server-search.png)
Searching with regex for the Server header.

![Literal string search for nginx, and exclusion of requests with no extension, js, php, and css.](./Images/literal-search.png)
Literal string search for nginx, and exclusion of requests with no extension, js, php, and css.

## Changelog

- v2.1 (11/08/2026)
  - The right-click menu on the results now offers four ways to copy instead of two, so you can take only the part you need
  - `Copy match only` copies the matched values on their own, without the host in front of them. It is also on `ctrl + shift + c`. Selecting a host copies all of its matches this way
  - `Copy all matches for <host>` copies everything found on a single host. The menu names the host, so you can see which one it will copy, and it works from a match row as well as from the host row — you no longer have to scroll back up to the host to copy its results. The host is copied exactly as it is shown, so it includes the protocol and port when those options are ticked
  - Copying now always follows the `Filter results` box. A filtered view copies only the rows it is showing, including when you copy a whole host
  - The extension is now built for Java 17, the version the Burp extension API itself targets. Previously the build used whichever Java version was installed on the machine that compiled it, which could produce a jar that Burp refuses to load, with no tab and nothing in the output log

- v2.0.1 (11/08/2026)
  - Fixed some regular expressions freezing the whole machine, not only Burp. A pattern such as `"\S+something/.*?"` could take minutes on a *single* response, and the extension used every CPU core while it did, so the desktop stopped responding. Burp's own memory usage looked normal throughout, which made it look like a hang rather than a slow search. It was worst on minified JavaScript and JSON, where a response is one very long line
  - Searches now skip messages that cannot possibly match. Before running your regex, the extension looks for a plain piece of text that every match has to contain and checks for that first, which is far cheaper. On test data this took a search that would have run for about an hour down to well under a second, with identical results
  - `Stop` now takes effect immediately. It could previously appear stuck on `Stopping...` while a slow match finished
  - The extension now leaves a CPU core free instead of always using four, so Burp and the rest of the machine stay usable during a search. This matters most on a VM or VDI with few cores

- v2.0 (06/08/2026)
  - Results are shown as a per-host tree with one match per row, replacing the `||` joined table cell
  - Result filter box, expand/collapse all, and a right-click copy menu
  - Reworked layout that follows Burp's own theme and fonts
  - Faster searches: message bodies are scanned in parallel and each message is read once instead of twice
  - Fixed literal searches being compiled as regular expressions, so terms such as `?` or `cache[` no longer fail silently
  - Fixed status code, scope and extension filters aborting the rest of the history search

- V1.3 (24/06/2024)
  - Option to stop the search
  - Option to also filter by protocol and port in the "Host" column of the results

- v1.2 (19/02/2024)
  - Improved memory usage
  - Multithreaded execution
  - Option to filter in Requests or Responses only
  - Improved regex parsing

## Development

For bugs and feature ideas open an issue here.  