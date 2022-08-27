Redwood is an internet content-filtering program.
It adds flexibility and granularity to the
filtering by classifying sites into multiple categories instead of just
“Allow” and “Block.”

Basic Architecture
==================

Redwood runs as an HTTP proxy server. It examines each HTTP message to
determine if it should be allowed to proceed. If so, it passes the
message on to its final destination. If not, it replaces the message
with a customizable page stating that the request is not allowed
(optionally giving the reason and providing a link for filing an
overblock request).

Redwood’s filtering is based on URLs and also, where applicable, on page
content.

Configuration File
==================

By default, the main configuration file is located at
`/etc/redwood/redwood.conf`. This path can be changed by using the `-c`
command line switch. Configuration options may be specified either in
the configuration file or as command-line switches. In the configuration
file, they may be specified either as `key = value` or as `key value`.
Comments are delimited with `#`. Values may be enclosed in double
quotes, with the usual backslash escapes. Additional configuration files
may be included by using the `include` directive.

An example configuration file:

    # Listen for connections on port 8000.
    http-proxy :8000

    # the template for the block page
    blockpage "/etc/redwood/block.html"

    # directory of static files to be served by the internal web server
    static-files-dir /etc/redwood/static

    # directory of CGI scripts to run by the internal web server
    cgi-bin /etc/redwood/cgi

    # the directory containing the category information
    categories /etc/redwood/categories

    # the file containing the Access Control List configuration
    acls /etc/redwood/acls.conf

    # the minimum total score from a blocked category needed
    # to block a page
    threshold 275

    # file configuring the content pruning
    content-pruning /etc/redwood/pruning.conf

    # file configuring URL query modification
    query-changes /etc/redwood/safesearch.conf

    # path to the access log
    access-log /var/log/redwood/access.log

Categories
==========

The configuration files for Redwood allow the user to establish any
number of categories corresponding to the types of content that he
wishes to block or to allow. As each HTTP message is processed, it is
assigned a score in each category, based on the filter lists that are
set up for that category. These scores are then used to determine
whether the page should be blocked.

Each category is a assigned an action: allow, block, or ignore. A page
will be blocked if the score for any category listed as `block` is
higher than the highest score for any category listed as `allow`. If a
category is listed as `ignore`, its score does not affect whether a page
is blocked or not. However, a page is not blocked unless the score for
the highest `block` category is greater than a certain configurable
threshold. This prevents overblocks of pages with almost no textual
content.

A category's action may also be set to `acl`. Then the category is ignored
in the process of finding the top-scoring category for the page, 
but it is available for ACLs to act on it, whenever the page's score in that category
is greater than zero.

The categories are stored in a directory whose location is specified in
the configuration file. Each subdirectory of that directory defines a
category (with the same name as the directory).

Each category’s directory contains a file named `category.conf` and any
number of rule-list files. A category named “mechanical” might have a
`category.conf` file like the following:

    description: Auto Repair
    action: allow

This configuration would mean that the category’s user-visible
description would be “Auto Repair” rather than “mechanical,” and that
pages that fall into the category would be allowed. The description
defaults to the category name, and the action defaults to `ignore`.
Actions can be overriden for specific users by the use of ACLs.
A `category.conf` file may also have the entry `invisible: true`; this
indicates that when a page is blocked because it belongs to that
category, the response will be an invisible image instead of the usual
block page.

The rule-list files define the rules used to calculate the category’s
score. Each rule-list file must have an extension of `.list`. (This rule
ensures that files ending in `.bak`, `.orig`, etc. are ignored.) It is a
plain-text file encoded in UTF-8. Comments are delimited with `#`. Here
is an example of a rule-list file that might be in the directory for the
“mechanical” category mentioned earlier:

    napaonline.com 200 # Give napaonline.com 200 points for this category.
    www.napaonline.com/catalog/ 50 # bonus points for NAPA's catalog

    default 150 # The following domains will each get 150 points.
    carquest.com
    autozone.com

    /t[iy]re/ 75 # Any page with tire or tyre in the URL will get 75 points.
    /parts/h 50 # A page with parts in the hostname will get 50 points

    <grease gun> 25 # 25 points for each occurrence of "grease gun" in the content
    <oil filter> 25 100 # 25 points for each occurrence, but no more than 100 total

    %909841dcf4d4c000ff7f00fe30820000 100 # A hash of an image from napaonline.com

There are four kinds of filter rules:

- URL matching

    A URL matching rule consists of a domain name, optionally followed
    by a path. After it, separated by a space, is the weight—the number
    of points that get added to this category’s score for sites that
    match the rule.

    A rule for a domain will also match subdomains: `napaonline.com`
    also matches `www.napaonline.com`. A rule with a path will also
    match longer paths: `www.napaonline.com/catalog` also matches
    `www.napaonline.com/catalog/result.aspx`.

    If a domain and a subdomain (or a path and a subdirectory) are both
    listed, the subdomain will effectively get the sum of the two
    weights. For example, if `xerox.com` were listed with 100 points,
    and `support.xerox.com` were listed with 50 points,
    `support.xerox.com` would actually get a score of 150 points.

	If the host in the URL is an IP address, it can by matched by an IP
	rule. An IP rule starts with `ip:` (with no space after the colon).
	Then it has an IP address or an IP address range in any of three forms:
	"10.1.10.0-10.1.10.255", "10.1.10.0-255", and "10.1.10.0/24".

- URL regular expressions

    A regular expression to match the URL is listed between slashes. The
    points are added to the category score for each page whose URL
    matches the regular expression. The URL is converted to lower case
    before comparing it to the regular expressions. The regular
    expression syntax is that supported by the RE2 library.

    A regular expression can be restricted to matching a certain part of
    the URL by adding a one-character suffix immediately after the final
    slash. A suffix of `h` matches the hostname (e.g. `www.google.com`),
    `d` matches the base domain name (e.g. `google`), `p` matches the
    path, and `q` matches the query.

- Content phrases

    Unlike the other two kinds of rules, these apply to the content of
    the page, not the URL. Phrases are enclosed between angle brackets.
    Before testing to see if a phrase matches, both the phrase and the
    page are simplified: capital letters are converted to lowercase, all
    characters that are not letters or digits are replaced by spaces,
    and multiple spaces are replaced by single spaces. Then the phrase
    weight is added to the page’s score for the category for each time
    the phrase is found on the page. But if the phrase has a second
    weight listed, no more than that amount will be added no matter how
    many times the phrase occurs. (In the example, if “oil filter”
    occurred more than four times, the additional occurrences wouldn’t
    count.)

    The content of the page is scanned for phrases only if phrase
    scanning is selected with the `phrase-scan` ACL action.

- Image Hashes

	Redwood can hash images using the library at
	https://github.com/andybalholm/dhash.
    The rule consists of a percent sign (`%`) followed by the
    32-character hash calculated by the dhash program.
	The hash my optionally be followed by a hyphen and a threshold,
	which is an integer specifying the number of bits that may be different
	for another hash to be considered to match this hash (this overrides the global dhash-threshold setting).

	Images are hashed only if hashing is selected with the
    `hash-image` ACL action.

There is also a `default` rule. It specifies what weight will be
assigned to rules that don’t specify a weight. It applies to all rules
without a specified weight between it and the next `default` rule or the
end of the file. If there is no `default` rule, the default weight is
zero.

Weights must be integers, but they may be negative. Negative weights can
be used to offset short, general matches with long, more-specific ones,
e.g.:

    <grease> 10
    <grease paint> -10

If a page is blocked based on its URL (i.e. by URL matching and/or URL
regular expressions), its content will not be evaluated because the page
will not be downloaded.

Access Control Lists (ACLs)
===========================

Much of Redwood’s functionality is configured with Access Control Lists
(ACLs). Each request is assigned a number of ACL tags, and then an
action is chosen based on those tags. For example:

    acl no-web user-ip 192.168.1.25
    block no-web

The first line creates an ACL tag `no-web`, and assigns it to all
requests coming from IP address 192.168.1.25. The second line causes all
requests with that tag to be blocked.

ACLs are checked at several points during the processing of a request:
before sending the request to the origin server, after receiving a
response, and after scanning the content for phrases. Each time, the
request may have different ACL tags, since more information is
available. Each stage also has a different set of possible actions,
although there is some overlap. (The `allow`, `block`, and
`block-invisible` actions are always available.)

Any number of ACL files can be loaded with the `acl` directive in the
configuration file. An ACL file can load other ACL files with a line
that contains `include` and the filename.

Assigning ACL Tags
------------------

ACL tags are assigned by lines starting with `acl`. These lines have the
format:

    acl tag-name attribute values

The `tag-name` can be any name that does not include spaces. The
`attribute` refers to some property of the request or response (listed
below). The `values` are a space-separated list; if any of them matches
the attribute’s value, the tag will be assigned. If there is more than
one `acl` line with the same tag name, the tag will be applied if any of
them matches (logical OR). An ACL may have a description associated with
it with a line like `describe tag-name A long description`.

In addition to the tags assigned by `acl` lines, a request is assigned a
tag for its highest-scoring category (if the score is above the
threshold). 
There is also an ACL `invalid-ssl`, which is automatically assigned to
CONNECT requests when the data being sent over the connection is not
valid SSL or TLS.
Another virtual ACL is `transparent`, which is assigned to 
TLS connections intercepted on the `transparent-https` port.

The following attributes are available:

- connect-port

	(request only) The destination port of a CONNECT request.
	This attribute never matches if the request method is not CONNECT.

- content-type

    (response only) The response’s media type, usually taken from the
    Content-Type header. This can also be a generic type, with an
    asterisk after the slash:

		acl images content-type image/*

- http-status

    (response only) The response's HTTP status code.
	If this is a multiple of 100, all status codes in that block of 100 will match.

- method

    The HTTP request method, such as `GET` or `POST`.

- referer

    The request’s Referer header. (This matches the same way as regular
    URL matching rules.)

- server-ip
	
	The server’s IP address, or a range of addresses
	(in CIDR format, or with a dash).
	This attribute only matches if the request URL contains a literal IP address;
	it does not do a DNS lookup.

		acl google server-ip 172.217.0.0/16

- time

    The current time.

		acl work-hours time MTWHF 9:00-17:00


    This attribute lets you select certain days of the week and/or
    ranges of times of the day. If the days of the week are specified,
    they must come first; they are abbreviated SMTWHFA. Any number of
    time ranges may be specified; the rule will match if the current
    time falls within any of them. Times must be in 24-hour format.

- url

    The URL requested. (This matches the same way as regular URL
    matching rules.)

- user-agent

	The User-Agent header.
	Instead of interpreting the remainder of the line as a list of values,
	this attribute interprets it as a single regular expression to be
	matched against the User-Agent string.
	The matching is case-insensitive.

- user-ip

    The user’s IP address, or a range of addresses (in CIDR format, or
    with a dash).

		acl managers 10.0.2.5 10.0.1.0/24 10.0.2.18-25


- user-name

    The username from HTTP proxy authentication.

ACL Actions
-----------

After the ACL tags are assigned, Redwood goes through the ACL files
looking for an action to perform. An action will be selected only if it
has all the tags specified in the action line. (And none of the negated
tags; if a tag in an action line is preceded by an exclamation point,
the request must not have that tag.) Since it goes through the files in
order, earlier action lines take precedence over later ones. If it gets
to the end of the file without finding a matching rule, it will use the
default action of the highest-scoring category. If there is no category
that scores over the threshold, the default action is `allow`.

An ACL action line may optionally have a description string at the end.
This is a double-quoted string whose value will be available to the block page template
as {{.RuleDescription}}.

- allow

    Allow the request to proceed.

- block

    Respond with an HTTP status code of 403, and send the standard block
    page.

- block-invisible

    Respond with HTTP 403, and send an invisible 1-pixel image instead
    of a block page.

- disable-proxy-headers

	Don't add headers that indicate that the request has passed through a proxy
	(X-Forwarded-For and Via).

- hash-image

    (response only) Calculate a hash of the image, and compare it to the
    hash rules. If the difference between this hash and the one in the rule
    is less than the number of bits specified with `--dhash-threshold` (or the hash's individual threshold),
	it matches.

    This action should only be applied when the content is an image:

        acl image content-type image/jpeg image/gif image/png
        hash-image image

- ignore-category

    Drop the highest-scoring category off the list of categories, and go
    through the ACL files again.

- log-content

	Log the page's content. 
	The `content-log-dir` configuration directive must be set.
	The page's content will be saved in that directory, with its MD5 hash as the filename.
	A line will be added to `index.csv` in that directory, linking the page's URL to its MD5 hash.

- phrase-scan

    (response only) Run a phrase scan on the page content. Normally this
    will be configured to depend on the content type:

		acl text content-type text/* application/xhtml+xml
		acl css content-type text/css
		phrase-scan text !css


- require-auth

    (request only) Send an HTTP 407 response if the request doesn’t have
    a Proxy-Authorization header.

- ssl-bump

    (CONNECT requests only) Activate the SSLBump feature, to filter
    HTTPS connections. (Transparently intercepted HTTPS connections
    produce a virtual CONNECT request inside Redwood, so they can be
    filtered too.)

URL Query Modification
======================

When processing an HTTP request, Redwood can modify the query parameters
in the URL. The configuration file for these changes is specified with
the `query-changes` keyword. Each line contains a URL-matching or
URL-regular-expression rule, followed by a query expression. If the
query in the URL already contains parameters with the same names as
those specified in the file, they will be replaced with the new values.
Otherwise the new values will be added.

    # Force safe search on several search engines.
    /www\.google\.[^/]+/search/ safe=vss
    search.lycos.com adv=1&adf=on
    search.yahoo.com vm=r
    /hotbot/h adf=on
    www.metacrawler.com familyfilter=1

Content Pruning
===============

Between downloading a page and scanning its content for phrases, Redwood
can perform “content pruning.” This is scanning the parsed HTML tree for
elements matching certain criteria, and deleting those elements and
their children.

Content pruning is controlled by a configuration file. Each line of the
file contains a URL-matching or URL-regular-expression rule to specify
what site or page the pruning applies to, and a CSS selector to specify
what elements to delete. Between the two, there may be a threshold
value. If a threshold is specified, the element and its children are
deleted after the page is phrase-scanned if
the score from the phrases found in a
blocked category is at least the threshold.


    # Craigslist personals and discussion forums
    craigslist.org div#ppp, div#forums, option[value=ppp]

    # Bing ad sidebar
    bing.com div.sb_adsNv2

    # Delete questionable forum topics.
    talk.newagtalk.com/forums 50 td.messagecellbody > ul

Block Pages
===========

When Redwood blocks access to a web page, it returns an HTTP response
with a status of 404 Forbidden. Unless the category that caused the page
to be blocked is configured as `invisible`, the body of the 404 response
will be HTML rendered from a template file. The template file is
specified with the `blockpage` configuration directive. The following
placeholders may be used in the template file, to be replaced by the
appropriate information when the block page is sent:

- {{.URL}}

    the URL of the page that was blocked

- {{.Categories}}

    the names of the categories that caused the page to be blocked

- {{.Conditions}}

    the conditions of the ACL rule that caused the page to be blocked

- {{.User}}

    the user’s IP address or username

- {{.Tally}}

    a list of the rules that matched, and how many times each one
    matched

- {{.Scores}}

    a list of categories, and how many points the page scored in each
    category

The block page is generated using the Go template package; see
`http://golang.org/pkg/text/template` and
`http://golang.org/pkg/html/template` for documentation.

There is one custom function defined for the templates to use, `eq`,
which tests its parameters for equality.

Virtual Web Servers
===================

Since the block page may need to refer to external resources (such as
images, stylesheets, and scripts), Redwood includes an internal web
server. This web server does not accept connections directly, but
whenever Redwood processes a request with a server address of
203.0.113.1, it directs the request to the internal server instead of
processing it normally. The content of the internal web server is
configured with the `static-files-dir`, and `cgi-bin` directives.

If a more advanced virtual server is needed, you can use the
`virtual-host` directive to transparently redirect requests for a given
hostname to a different address, such as an Apache web server running on
your gateway. If the server is running on your gateway, listening on
port 8888, and you want it to be available as `myserver.local`, use
`virtual-host myserver.local localhost:8888`. (Note: proxy settings are
not set on the client, and Redwood is intercepting requests
transparently, this will work only if the DNS server resolves the name
to an IP address outside your local network. Any IP address will do,
though. OpenDNS’s website-unavailable address works fine. Also note that
`virtual-host` only works with HTTP, not with HTTPS.)

Test Mode
=========

If Redwood is run with the `-test` switch, it does not run as a proxy
server. Instead, it evaluates the URL given as an argument after the
switch. It prints detailed debugging information about how the URL and
its content would be rated if that page were requested in normal
operation: how many times each rule matches, what the score is in each
category, which categories would block the page, etc.

Log Files
=========

Redwood has several categories of messages that can be logged:

General diagnostic messages are sent to standard error by default, and
may be redirected to a file using normal shell redirection.

The access log has a line for each request processed. It is in CSV
format and goes to standard output by default. It can be sent to a file
by including the `access-log` directive in Redwood’s configuration file.
The access log has the following fields: time, username or IP address,
action (allow or block), URL, HTTP method (GET, PUT, etc.),
HTTP response status (if an HTTP response was being processed), content
type, content-length, whether the content was modified by Redwood, which
rules matched (and how many times), the score for each category, the
list of categories that caused the page to be blocked (if it was),
the page title (if `log-title` is enabled),
a list of the categories that were ignored even though they had higher
scores than the one that determined the action,
the User-Agent header (if `log-user-agent` is enabled),
the HTTP version,
the Referer header,
the client platform (such as Windows or iPad, found in the User-Agent header),
the filename from the Content-Disposition header (for downloaded files),
the virus-scan result,
the rule’s description,
and the client’s IP address.
The content length is meaningful only if a phrase scan was performed.
The page title is available only if a phrase scan was performed and
`log-title` was enabled in the configuration (logging the page title
requires parsing the HTML, so it is disabled by default).

The TLS log has a line for each HTTPS connection that was intercepted.
Like the access log, it goes to standard output by default, and it can
be sent to a file with the `tls-log` directive. The TLS log has the
following fields: time, username or client IP address, server name,
server address, any error that was encountered, 
and whether the certificate used came from the certificate cache.

Authentication
==============

Redwood can be configured (using the `require-auth` ACL action) to
require HTTP basic proxy authentication, with a username and password.
The usernames and passwords can come from a file that is specified by
the `--password-file` configuration directive.
Each line in the file
consists of a username, a password, and some optional items,
separated by spaces or tabs.
Alternatively,
a program can be specified to perform authentication with
`--authenticator`.
The program will be invoked with the username and password as 
command-line arguments.
Its exit status determines whether the authentication is successful;
if the exit status is zero, the user will be accepted.

The optional items in the password file are for setting up a custom proxy port
for that individual user, to make authentication easier.
The first optional item is a port number; if it is present,
Redwood will listen for HTTP requests on that port.
Only the specified user may use that port,
but once a client has authenticated as that user,
all further requests from that IP address to this port will be considered authenticated,
whether they have the Proxy-Authorization header or not.

In addition, you can set up automatic authentication based on the device platform
and the network the device is on.
For example, to automatically authenticate an iPad on the Verizon network,
you could have the following line in the password file:

    ipad-user mySecurePassword 7500 iPad myvzw.com

Redwood uses the HTTP User-Agent string to determine a device's platform.
The currently recognized platforms are Windows, Linux, Android, Macintosh,
iPhone, iPad, and iPod.)

The network can be specified as an IP address range in CIDR notation (70.192.0.0/11)
or as a domain name to be compared to an IP address's reverse DNS entry.
Multiple networks can be specified, separated by commas.
If a device successfully authenticates (using the username and password)
from a network that is not on the list, that network will be added to the list of expected networks. 

You can configure certain IP addresses (normally LAN addresses)
to be pre-authenticated as specific users by specifying a mapping 
file with the `ip-to-user` option. The file must be formatted like this:

	192.168.1.66 joe_pc
	192.168.1.87 fred_pc

In this example, requests coming from 192.168.1.66 would be automatically 
authenticated as `joe_pc`, and requests coming from 192.168.1.87
would be authenticated as `fred_pc`.

SSLBump
=======

Redwood can be configured (using the `ssl-bump` ACL action) to perform
Man-in-the-Middle filtering of HTTPS traffic. This feature is called
SSLBump after the corresponding feature in Squid.

For SSLBump to work, Redwood must be configured with a root certificate
that is trusted by the users’ browsers. Paths to the certificate and its
private key are specified with the `tls-cert` and `tls-key` options. The
certificate and key should be in PEM format.

Redwood uses the system root certificates to verify the identity of the
sites it bumps. Other trusted root certificates can be specified with
the `trusted-root` option.

The SSLBump feature only works with SSL version 3 and newer (including all TLS versions).
By default, earlier versions are passed through unfiltered.
It can be configured to block them instead with the `block-obsolete-ssl` option.

Transparent Proxy
=================

With the proper firewall setup, Redwood can transparently intercept
connections to web servers and filter them without needing to configure
proxy settings on the client computers.
Intercepted HTTP connections can use the same proxy port as is used
for manually-configured proxy connections.
For HTTPS connections, Redwood must be configured to listen for
intercepted connections on a separate port, with the `transparent-https`
directive.

The following configuration lines will set Redwood to listen on
ports 6502 and 6510:

	http-proxy :6502
	transparent-https :6510

If Redwood is running on a Linux gateway/router system,
the following iptables rules will enable transparent
filtering for the computers on the LAN
(assuming that the LAN interface is `eth1`):

	iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-ports 6502
	iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 443 -j REDIRECT --to-ports 6510

To do the same thing with pf on a FreeBSD gateway
(assuming that the LAN interface is `re0`):

	table <filtered> { re0:network }
	rdr pass inet proto tcp from <filtered> to any port 80 -> re0 port 6502
	rdr pass inet proto tcp from <filtered> to any port 443 -> re0 port 6510

Classification Service
======================

In addition to running as a proxy, Redwood can also be used as a URL classification service.
It receives an HTTP request specifying a URL, and returns a JSON object that tells
what categories it was classifed in, and the score for each category.

Categories can be excluded from the classification reports:

	classifier-ignore sslbump
	classifier-ignore masterwhitelist

The classification request must have the URL as an HTTP form parameter named "url."
The JSON object in the response has the following keys:

 - url: the URL being classified
 - categories: an object with category names for keys, and their scores for values
 - error: any error that was encountered fetching or processing the page

For example, if Redwood is running on port 6502 on 10.1.10.1,
http://10.1.10.1:6502/classify?url=https%3A%2F%2Fgolang.org might return
{"url":"https://golang.org","categories":{"computer":266}}.

It can also classify text directly. 
http://10.1.10.1:6502/classify-text?text=programming+language
might return {"text":"programming language","categories":{"computer":27}}.

PAC Files
=========

Redwood can provide PAC (Proxy Auto-Configuration) files to automatically configure
client computers to use it as their proxy.
Then, whenever Redwood receives a request for `/proxy.pac`,
it sends a PAC file directing the client to proxy its requests.

PAC files also make another feature possible:
listening on separate, pre-authenticated ports for individual users.
This helps to address various authentication problems resulting from software that
doesn't support proxy authentication properly.
To enable this, specify a custom port number on the user's line in the password file.
Then, put a base64-encoded username/password pair (just like in an HTTP basic authentication header)
in the PAC request URL (e.g. `/proxy.pac?a=dXNlcm5hbWU6cGFzc3dvcmQ=`).
(Generate it by typing a command like `echo -n username:password | base64` at a UNIX command prompt.)
All requests received on that port from the same IP address as the PAC file request will be automatically
authenticated as that user.

For devices that require an HTTPS PAC URL, an upstream proxy can be configured to handle the TLS termination.
The reverse proxy config must set the `X-Forwarded-For` header so that Redwood can authenticate the correct 
IP Address. Also, the `X-Forwarded-Host` header should be set to return the hostname and default proxy port.

```
# Nginx example location block
location /proxy.pac {
    proxy_pass http://127.0.0.1:6502/proxy.pac;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Host $host:6502;
}
```

Scripting
=========

To further customize its behavior,
Redwood lets you define scripts that are run at various points as it processes a request.
The original JavaScript scripting is described below.
The newer Starlark scripting is described in the file starlark.md.

For more specialized rules than the ones that are supported by normal ACLs,
you can write scripts (in JavaScript) that assign ACLs to requests.
For example, suppose you want to block the sites that OpenDNS classifies
as adult or phishing sites,
but you want to have your own block page instead of the one OpenDNS provides.
You could put a script like this in `/etc/redwood/opendns.js`:

```js
var openDNSResult = lookupHost(request.URL.Host, "208.67.222.123");

if (openDNSResult == "146.112.61.106") {
	addACL("opendns-adult");
} else if (openDNSResult == "146.112.61.108") {
	addACL("opendns-phishing");
}
```

Put the following line in `redwood.conf`:

    request-acl-script /etc/redwood/opendns.js

And in your ACL configuration file:

    block opendns-adult
    block opendns-phishing


