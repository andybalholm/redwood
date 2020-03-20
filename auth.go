package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

func (c *config) send407(w http.ResponseWriter) {
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
	if conf.ExtraRootCerts != nil {
		client.Transport = &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				// Dial a TLS connection, and make sure it is valid against either the system default
				// roots or conf.ExtraRootCerts.
				serverName, _, _ := net.SplitHostPort(addr)
				conn, err := tls.DialWithDialer(dialer, network, addr, &tls.Config{
					ServerName:         serverName,
					InsecureSkipVerify: true,
				})
				if err != nil {
					return nil, err
				}
				state := conn.ConnectionState()
				serverCert := state.PeerCertificates[0]

				chains, err := serverCert.Verify(x509.VerifyOptions{
					Intermediates: certPoolWith(state.PeerCertificates[1:]),
					DNSName:       serverName,
				})
				if err == nil {
					state.VerifiedChains = chains
					return conn, nil
				}

				chains, err = serverCert.Verify(x509.VerifyOptions{
					Intermediates: certPoolWith(state.PeerCertificates[1:]),
					DNSName:       serverName,
					Roots:         conf.ExtraRootCerts,
				})
				if err == nil {
					state.VerifiedChains = chains
					return conn, nil
				}

				return nil, err
			},
		}
	} else {
		client.Transport = httpTransport
	}

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
		return resp.StatusCode == 200
	})

	return nil
}
