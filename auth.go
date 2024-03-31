package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"go.starlark.net/starlark"
)

// HTTP proxy authentication.

func (c *config) readPasswordFile(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("could not open %s: %s", filename, err)
	}
	defer f.Close()
	cr := newConfigReader(f)

	for {
		line, err := cr.ReadLine()
		if err != nil {
			break
		}

		words := strings.Fields(line)

		switch len(words) {
		case 2:
			c.Passwords[words[0]] = words[1]

		case 3:
			user, pass, portStr := words[0], words[1], words[2]
			c.Passwords[user] = pass
			port, err := strconv.Atoi(portStr)
			if err != nil {
				log.Printf("invalid port number %q in password file line: %s", portStr, line)
				continue
			}
			c.CustomPorts[user] = customPortInfo{
				Port: port,
			}
			c.UserForPort[port] = user

		case 4:
			user, pass, portStr, clientPlatform := words[0], words[1], words[2], words[3]
			c.Passwords[user] = pass
			port, err := strconv.Atoi(portStr)
			if err != nil {
				log.Printf("invalid port number %q in password file line: %s", portStr, line)
				continue
			}
			c.CustomPorts[user] = customPortInfo{
				Port:           port,
				ClientPlatform: clientPlatform,
			}
			c.UserForPort[port] = user

		case 5:
			user, pass, portStr, clientPlatform, networks := words[0], words[1], words[2], words[3], words[4]
			c.Passwords[user] = pass
			port, err := strconv.Atoi(portStr)
			if err != nil {
				log.Printf("invalid port number %q in password file line: %s", portStr, line)
				continue
			}
			c.CustomPorts[user] = customPortInfo{
				Port:             port,
				ClientPlatform:   clientPlatform,
				ExpectedNetworks: strings.Split(networks, ","),
			}
			c.UserForPort[port] = user

		default:
			log.Println("malformed line in password file:", line)
		}
	}

	return nil
}

func send407(w http.ResponseWriter) {
	c := getConfig()
	w.Header().Set("Proxy-Authenticate", "Basic realm="+c.AuthRealm)
	http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
}

// ProxyCredentials returns the username and password from r's
// Proxy-Authorization header.
func ProxyCredentials(r *http.Request) (user, pass string, ok bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Basic ") {
		return "", "", false
	}

	return decodeBase64Credentials(strings.TrimPrefix(auth, "Basic "))
}

// decodeBase64Credentials decodes a base64-encoded username:password pair
// such as those used in HTTP basic authentication.
func decodeBase64Credentials(auth string) (user, pass string, ok bool) {
	auth = strings.TrimSpace(auth)
	enc := base64.StdEncoding
	buf := make([]byte, enc.DecodedLen(len(auth)))
	n, err := enc.Decode(buf, []byte(auth))
	if err != nil {
		return "", "", false
	}
	auth = string(buf[:n])

	colon := strings.Index(auth, ":")
	if colon == -1 {
		return "", "", false
	}

	return auth[:colon], auth[colon+1:], true
}

// ValidCredentials returns whether user and password are a valid combination.
func (conf *config) ValidCredentials(user, password string) bool {
	conf.PasswordLock.RLock()
	ok := password == conf.Passwords[user] && password != ""
	conf.PasswordLock.RUnlock()
	if ok {
		return true
	}

	for _, a := range conf.Authenticators {
		if a(user, password) {
			if _, ok := conf.Passwords[user]; !ok {
				// Cache the password for later use.
				conf.PasswordLock.Lock()
				conf.Passwords[user] = password
				conf.PasswordLock.Unlock()
			}
			return true
		}
	}
	return false
}

func (conf *config) addAuthenticator(path string) error {
	conf.Authenticators = append(conf.Authenticators, func(user, password string) bool {
		cmd := exec.Command(path, user, password)
		err := cmd.Run()
		return err == nil
	})

	return nil
}

func (conf *config) addHTTPAuthenticator(endpoint string) error {
	var client http.Client
	client.Transport = transportWithExtraRootCerts

	conf.Authenticators = append(conf.Authenticators, func(user, password string) bool {
		formData := make(url.Values)
		formData.Set("username", user)
		formData.Set("password", password)
		resp, err := client.Post(endpoint, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
		if err != nil {
			log.Printf("Error communicating with authentication API endpoint %s: %v", endpoint, err)
			return false
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return false
		}

		var userInfo struct {
			DeviceGroups []string `json:"device_groups"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&userInfo); err == nil {
			conf.ACLs.ExternalDGLock.Lock()
			if conf.ACLs.ExternalDeviceGroups == nil {
				conf.ACLs.ExternalDeviceGroups = map[string][]string{}
			}
			conf.ACLs.ExternalDeviceGroups[user] = userInfo.DeviceGroups
			conf.ACLs.ExternalDGLock.Unlock()
		} else {
			log.Printf("Error decoding authenticator-api response for %s: %v", user, err)
		}

		return true
	})

	return nil
}

func (c *config) loadIPToUser(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("could not open %s: %s\n", filename, err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) > 2 && strings.HasPrefix(fields[2], "#") {
			fields = fields[:2]
		}

		if len(fields) != 2 {
			log.Printf("Syntax error in %s: %q", filename, line)
			continue
		}

		c.IPToUser[fields[0]] = fields[1]
	}

	return s.Err()
}

// UserInfo represents a user who is attempting to authenticate with the proxy.
type UserInfo struct {
	ClientIP          string
	AuthenticatedUser string
	Request           *http.Request

	frozen bool
}

// Authenticate uses the information from u.Request to attempt to authenticate the user.
// It fills in ClientIP, and (if the authentication is successful) AuthenticatedUser.
func (u *UserInfo) Authenticate(p *perUserProxy) {
	u.ClientIP = u.Request.RemoteAddr
	if host, _, err := net.SplitHostPort(u.ClientIP); err == nil {
		u.ClientIP = host
	}

	if u.Request.Header.Get("Proxy-Authorization") != "" {
		user, pass, ok := ProxyCredentials(u.Request)
		if ok {
			if getConfig().ValidCredentials(user, pass) {
				u.AuthenticatedUser = user
			} else {
				logAuthEvent("proxy-auth-header", "invalid", u.Request.RemoteAddr, 0, user, pass, "", "", u.Request, "Incorrect username or password")
			}
		} else {
			logAuthEvent("proxy-auth-header", "invalid", u.Request.RemoteAddr, 0, "", "", "", "", u.Request, "Invalid auth header")
		}
	} else if user, ok := getConfig().IPToUser[u.ClientIP]; ok {
		u.AuthenticatedUser = user
	}

	if p != nil && u.AuthenticatedUser == "" {
		configuredUser := getConfig().UserForPort[p.Port]
		expectedNetwork := false
		ip := net.ParseIP(u.ClientIP)
		p.expectedNetLock.RLock()
		expectedPlatform := p.ClientPlatform
		for _, nw := range p.expectedIPBlocks {
			if nw.Contains(ip) {
				expectedNetwork = true
				break
			}
		}
		p.expectedNetLock.RUnlock()

		domain := rdnsDomain(u.ClientIP)
		if !expectedNetwork && domain != "" {
			p.expectedNetLock.RLock()
			expectedNetwork = p.expectedDomains[domain]
			p.expectedNetLock.RUnlock()
		}

		if expectedNetwork {
			derivedPlatform := platform(u.Request.Header.Get("User-Agent"))
			if expectedPlatform != "" && derivedPlatform == expectedPlatform || darwinPlatforms[expectedPlatform] && derivedPlatform == "Darwin" {
				logAuthEvent("expected-network", "correct", u.ClientIP, p.Port, configuredUser, "", derivedPlatform, domain, u.Request, "Authenticated via expected platform and network")
				u.AuthenticatedUser = configuredUser
			}
		}
	}

	if p == nil {
		callStarlarkFunctions("authenticate", u, starlark.None)
	} else {
		callStarlarkFunctions("authenticate", u, p)
	}
}

func (u *UserInfo) String() string {
	return fmt.Sprintf("UserInfo(%s)", u.Request.RemoteAddr)
}

func (u *UserInfo) Type() string {
	return "UserInfo"
}

func (u *UserInfo) Freeze() {
	if !u.frozen {
		u.frozen = true
	}
}

func (u *UserInfo) Truth() starlark.Bool {
	return starlark.True
}

func (u *UserInfo) Hash() (uint32, error) {
	return 0, errors.New("unhashable type: UserInfo")
}

var userInfoAttrNames = []string{"authenticated_user", "ip", "user_agent", "platform", "proxy_auth"}

func (u *UserInfo) AttrNames() []string {
	return userInfoAttrNames
}

func (u *UserInfo) Attr(name string) (starlark.Value, error) {
	switch name {
	case "authenticated_user":
		return starlark.String(u.AuthenticatedUser), nil
	case "ip":
		return starlark.String(u.ClientIP), nil
	case "user_agent":
		return starlark.String(u.Request.Header.Get("User-Agent")), nil
	case "platform":
		return starlark.String(platform(u.Request.Header.Get("User-Agent"))), nil
	case "proxy_auth":
		user, pass, ok := ProxyCredentials(u.Request)
		if ok {
			return starlark.Tuple{starlark.String(user), starlark.String(pass)}, nil
		} else {
			return starlark.None, nil
		}

	default:
		return nil, nil
	}
}

func (u *UserInfo) SetField(name string, val starlark.Value) error {
	if u.frozen {
		return errors.New("can't set a field of a frozen object")
	}

	switch name {
	case "authenticated_user":
		return assignStarlarkString(&u.AuthenticatedUser, val)
	default:
		return starlark.NoSuchAttrError(fmt.Sprintf("can't assign to .%s field of UserInfo", name))
	}
}
