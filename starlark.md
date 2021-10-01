# Starlark Scripting

Starlark is an embeddable scripting language based on Python.
Redwood uses the Go implementation from https://github.com/google/starlark-go.

It loads Starlark script files specified with `starlark-script` in the configuration,
collects the functions defined there, 
and calls the functions with certain names as it processes a request.

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

`TLSSession` also has methods to directly set what action Redwood will take for the request:

- `intercept`: intercept the TLS session as a man-in-the-middle,
  to filter the HTTPS requests inside. (This is equivalent to the `ssl-bump` ACL action.)

- `bypass`: don't intercept the TLS session; just connect directly to the origin server.

- `block`: close the connection immediately.

### `filter_request`

For each HTTP request that Redwood receives, it calls the `filter_request` function.
The function’s parameter isa `Request` object,
which gives information about the request and lets you customize how Redwood handles it.

The `Request` object has the following attributes:

- `client_ip`: the client computer's IP address.

- `user`: the username that the client has authenticated with.

- `method`: the HTTP method (`GET`, `POST`, etc.) of the request.

- `url`: the URL being fetched by the request.
  It can be changed to fetch a different URL.
  (But with HTTPS requests, you can't change what server it comes from;
  that would need to be done at the `ssl_bump` stage.)

- `host`: the server name from the URL or from the `Host` header.

- `path`: the request’s URL path. It can be changed to fetch a different URL.

- `acls`: a set containing the ACL tags that have been assigned to the request. 
  If you modify the set, it can affect the action that Redwood takes.

- `scores`: a dictionary containing the category scores that have been assigned to the request.
  (The keys are strings, and the values are integers.)
  If you modify the dictionary, it can affect the action that Redwood takes.

There are methods to get and set the URL’s query parameters:

- `param("q")` returns the value of the `q` query parameter.

- `set_param(q="redwood")` sets the `q` parameter to "redwood",
  either adding it, or replacing an existing parameter.
  Multiple parameters may be set at once: `set_param(q="redwood", safe="vss")`.

- `delete_param("q")` removes the `q` query parameter. 
  Multiple parameters may be deleted at once: `delete_param("utm_content", "utm_medium")`.

There are methods to get and set the request’s HTTP headers:

- `header("User-Agent")` returns the value of the User-Agent header.

- `set_header(user_agent="Mozilla")` sets the User-Agent header to "Mozilla".
  Note that underscores are used instead of hyphens in the header name, 
  to make the syntax work for keyword parameters.
  Multiple headers may be set at once.

- `delete_header("User-Agent")` removes the User-Agent header.
  Multiple headers may be deleted at once.

`Request` also has methods to directly set what action Redwood will take for the request:

- `allow`: don’t block the request (though it could still be blocked at the response stage).

- `block`: block the request and show a block page.

- `block_invisible`: block the request and send a small transparent image instead of a block page.


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
