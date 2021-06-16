# Starlark Scripting

Starlark is an embeddable scripting language based on Python.
Redwood uses the Go implementation from https://github.com/google/starlark-go.

It loads Starlark script files specified with `starlark-script` in the configuration,
collects the functions defined there, 
and calls the functions with certain names as it processes a request.

(At this point the only function that is supported is `ssl_bump`.)

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

TLSSession also has methods to directly set what action Redwood will take for the request:

- `intercept`: intercept the TLS session as a man-in-the-middle,
  to filter the HTTPS requests inside. (This is equivalent to the `ssl-bump` ACL action.)

- `bypass`: don't intercept the TLS session; just connect directly to the origin server.

- `block`: close the connection immediately.

## Language and Library Notes

The Go implementation of Starlark has several features that are not present in the Java version.
Some of them are optional.
Redwood enables all the optional features (set, lambda, recursion, and reassigning global variables).
It imports the `json`, `math`, and `time` modules that are available in the Starlark REPL,
and several modules from github.com/qri-io/starlib (`base64`, `bsoup`, `csv`, `hash`, `html`, `http`, `re`, and `yaml`).

### Predefined Functions

- `lookup_host`: does a DNS lookup and returns the IP address.
  You can do the lookup with your system’s default DNS resolver (`lookup_host("www.google.com")`),
  or specify a specific DNS server to use (`lookup_host("www.google.com", "208.67.222.123")`).
