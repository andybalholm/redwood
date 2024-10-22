# Starlark Scripting

Starlark is an embeddable scripting language based on Python.
Redwood uses the Go implementation from https://github.com/google/starlark-go.

It loads Starlark script files specified with `starlark-script` in the configuration,
collects the functions defined there, 
and calls the functions with certain names as it processes a request.
If there are multiple functions defined with the same name (in separate files),
they will be called in the order they were defined.

## An Example

If you want to use a Starlark script to turn on Google safe search,
put this in `/etc/redwood/safesearch.star`:

```python
def ssl_bump(session):
    if session.sni in ("www.google.com", "google.com"):
         session.server_addr = "forcesafesearch.google.com:443"
```

And add this line to `/etc/redwood/redwood.conf`:

    starlark-script /etc/redwood/safesearch.star

Each time Redwood intercepts an HTTPS connection, 
it will call the `ssl_bump` function you defined.
So if the Server Name Indication (SNI) of the connection is www.google.com or google.com,
it will connect to forcesafesearch.google.com instead.

## Functions You Can Define

### `authenticate`

When Redwood is checking the authentication for a request, it calls the `authenticate` function.
This happens after the default authentication steps have been performed, 
and allows the script to de-authenticate a user that would normally have been authenticated,
or to authenticate a user that normally would not have been authenticated.
The function has two parameters, a `UserInfo` object and a `CustomPort` object
(or `None` if the request was not received on a per-user proxy port).

The `UserInfo` object has the following attributes:

- `authenticated_user`: the username that the client has successfully authenticated as,
  or the empty string if there is no authenticated user.
  Changing this attribute changes the authentication status of the request.

- `ip`: the client’s IP address

- `user_agent`: the User-Agent header from the request

- `platform`: the operating-system platform implied by the User-Agent header

- `proxy_auth`: a 2-element tuple containing the username and password from
  the Proxy-Authorization header, or `None` if that header is missing or invalid.

The `CustomPort` object has the following attributes:

- `port`: the port number

- `user`: the username the port is configured for

- `platform`: the operating-system platform specified in the password file

- `expected_networks`: a tuple of strings listing the networks 
  (domains or IP address blocks) that the user is expected to connect from

### `ssl_bump`

When Redwood intercepts an HTTPS connection, it calls the `ssl_bump` function.
The function's parameter is a `TLSSession` object, 
which gives information about the connection and lets you customize how Redwood handles it.

The `TLSSession` object has the following attributes:

- `client_ip`: the client computer's IP address.

- `user`: the username that the client has authenticated with.

- `sni`: the Server Name Indication (SNI) from the TLS connection's client hello message.
  This is normaly the hostname from the URL the user typed into his browser.

- `server_addr`: the address (in host:port format) of the upstream server that Redwood will connect to.
  If you change this, it will connect to the server you specify.

- `source_ip`: the address of the network interface that should be used for the connection to the origin server.
  This is blank by default, but you can set it to control what network interface will 
  be used to connect to the origin server.

- `acls`: a set containing the ACL tags that have been assigned to the request. 
  If you modify the set, it can affect the action that Redwood takes.

- `scores`: a dictionary containing the category scores that have been assigned to the request.
  (The keys are strings, and the values are integers.)
  If you modify the dictionary, it can affect the action that Redwood takes.

- `action`: a string indicating what action Redwood will take for the connection.

- `possible_actions`: a tuple of strings, listing the values that may be assigned to `action`.

- `header`: the header from the HTTP CONNECT request that initiated this session, if any.
  (Sessions that were transparently intercepted do not have a CONNECT request.)

- `misc`: a dictionary-like object where the script can store miscellaneous data.
  (Rather than a regular dictionary, it's a concurrency-safe wrapper around one.)

- `log_data`: the script can put data here to be included in the access log, encoded as JSON

- `id`: a random ID that is generated for each session

### `inspect_server_certificate`

When Redwood is acting as man-in-the-middle on an HTTPS connection,
it calls `inspect_server_certificate` 
after completing the TLS handshake with the server, 
but before completing the handshake with the client.
The parameter for this function is the same `TLSSession` object
as in `ssl_bump`, but with additional attributes:

- `server_ip`: the IP address of the server

- `server_certificate`: an object giving access to various properties of the
  upstream server’s TLS certificate.

### `filter_request`

For each HTTP request that Redwood receives, it calls the `filter_request` function.
The function’s parameter is a `Request` object,
which gives information about the request and lets you customize how Redwood handles it.

The `Request` object has the following attributes:

- `session`: the TLSSession object for the connection this request was received on
  (if it is an HTTPS request), or None.

- `client_ip`: the client computer's IP address.

- `user`: the username that the client has authenticated with.

- `expected_user`: the expected username, based on which port the request was received on.
  (If the request was received on a per-user port but not authenticated,
  `expected_user` will be set, but `user` will be empty.)

- `local_port`: the port the request was received on.

- `authenticated_clients`: the IP addresses that have successfully authenticated
  on the same port this request was received on, with a username equal to `expected_user`.

- `method`: the HTTP method (`GET`, `POST`, etc.) of the request.

- `url`: the URL being fetched by the request.
  It can be changed to fetch a different URL.

- `host`: the server name from the URL or from the `Host` header.

- `path`: the request’s URL path. It can be changed to fetch a different URL.

- `header`: a dictionary containing the request’s HTTP headers.

- `query`: a dictionary containg the request’s URL query parameters.

- `body`: The request’s body content, as a string. Assigning to body replaces the
  request’s content.

- `acls`: a set containing the ACL tags that have been assigned to the request. 
  If you modify the set, it can affect the action that Redwood takes.

- `scores`: a dictionary containing the category scores that have been assigned to the request.
  (The keys are strings, and the values are integers.)
  If you modify the dictionary, it can affect the action that Redwood takes.

- `action`: a string indicating what action Redwood will take for the request.

- `possible_actions`: a tuple of strings, listing the values that may be assigned to `action`.

- `misc`: a dictionary where the script can store miscellaneous data

- `log_data`: the script can put data here to be included in the access log, encoded as JSON

### `filter_response`

For each HTTP response that Redwood receives, it calls the `filter_response` function.
The function’s parameter is a `Response` object,
which gives information about the response and lets you customize how Redwood handles it.

The `Response` object has the following attributes:

- `request`: the Request object for the associated HTTP request.

- `status`: the HTTP status code.
  It can be changed to affect the status code the client receives.

- `body`: The response’s body content, as a string. Assigning to body replaces the
  response’s content. If the body is larger than `max-content-scan-size`, `body` will be `None`.

- `html`: A `SoupNode` containing the parsed HTML content of the response,
   or `None` if the content is not HTML or the content is larger than `max-content-scan-size`.

- `header`: a dictionary containing the response’s HTTP headers.

- `acls`: a set containing the ACL tags that have been assigned to the response.
  If you modify the set, it can affect the action that Redwood takes.

- `scores`: a dictionary containing the category scores that have been assigned to the response.
  (The keys are strings, and the values are integers.)
  If you modify the dictionary, it can affect the action that Redwood takes.

- `action`: a string indicating what action Redwood will take for the request.

- `possible_actions`: a tuple of strings, listing the values that may be assigned to `action`.

- `misc`: a dictionary where the script can store miscellaneous data

- `log_data`: the script can put data here to be included in the access log, encoded as JSON

Other methods of `Response`:

- `thumbnail(500)`: returns a JPEG thumbnail of the response, no more than 500 pixels in width and height.
  If no thumbnail is available (either because the response body is not a supported image format,
  or because the body is too large), `thumbnail` returns `None`.
  The default size is 1000 pixels.

## Language and Library Notes

The Go implementation of Starlark has several features that are not present in the Java version.
Some of them are optional.
Redwood enables all the optional features (set, lambda, recursion, and reassigning global variables).
It imports the `json`, `math`, and `time` modules that are available in the Starlark REPL,
and several modules from github.com/qri-io/starlib (`base64`, `bsoup`, `csv`, `hash`, `html`, `http`, `re`, and `yaml`).

The output from Starlark functions (`print` statements and error tracebacks)
goes to a CSV log file specified with the `starlark-log` configuration option.

### Predefined Functions

- `lookup_host`: does a DNS lookup and returns the IP address.
  You can do the lookup with your system’s default DNS resolver (`lookup_host("www.google.com")`),
  or specify a specific DNS server to use (`lookup_host("www.google.com", "208.67.222.123")`).

- `lookup_addr`: does a reverse DNS lookup and returns the hostname.
  You can do the lookup with your system’s default DNS resolver(`lookup_addr("8.8.8.8")`),
  or specify a specific DNS server to use (`lookup_addr("8.8.8.8", "208.67.222.123")`).
  The trailing dot that is normally returned by a reverse DNS query is stripped off.

- `urlparse`: parses a URL from a string to a named tuple,
  largely compatible with Python’s `urllib.parse.urlparse`.

- `parse_qs`: parses a URL query string, to a dict of tuples,
  largely compatible with Python’s `urllib.parse.parse_qs`.

- `publicsuffix`: returns the public suffix of a domain

- `privatesuffix`: returns one more label than the public suffix

### Caches

Redwood provides a `Cache` type that scripts can use to temporarily store the results of 
calculations or network lookups.
Caches have names, and are shared between scripts. 
To get a cache, call `Cache(name, size)`.
This either creates a cache with the specified name, or returns the cache that has already
been created with that name.
It sets the cache’s capacity (in number of items).

The cache’s keys must be strings; the values can be any type.

A `Cache` has the following methods:

- `set(key, val, ttl)`: stores a value in the cache.
  The ttl is an optional `time.duration` value that specifies when the entry will expire.
  If it is omitted, the entry will stay in the cache until it is displaced by adding another entry.

- `get(key)`: returns the last value that was stored with that key,
  or `None` if the key is not found in the cache (either because it hasn’t been stored there
  or because the entry has expired or been replaced).

- `del(key)`: removes an entry from the cache.

### Log Files

Redwood provides a `CSVLog` type that scripts can use to write data to CSV log files.
To open a log file, call `CSVLog(path)`.
A `CSVLog` has one method:

- `log`: converts its arguments to strings, and writes them as a line in the log file.
  It adds a column a the start of the line with the current date and time.
