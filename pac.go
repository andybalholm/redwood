package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var perUserPorts chan int

// handlePACFile serves an automatically-generated PAC (Proxy Auto-Config) file
// pointing to this proxy server.
func handlePACFile(w http.ResponseWriter, r *http.Request) {
	conf := getConfig()

	proxyAddr := conf.PACAddress

	client := r.RemoteAddr
	host, _, err := net.SplitHostPort(client)
	if err == nil {
		client = host
	}
	if lanAddress(client) && conf.PACLANAddress != "" {
		proxyAddr = conf.PACLANAddress
	}

	user, pass := r.FormValue("u"), r.FormValue("p")
	if perUserPorts != nil && user != "" && pass != "" && conf.ValidCredentials(user, pass) {
		// Open a separate, pre-authenticated listener for this user.
		port := <-perUserPorts
		proxyHost, _, err := net.SplitHostPort(proxyAddr)
		if err != nil {
			log.Printf("invalid pac-address value (%q)", proxyAddr)
			http.Error(w, "can't generate PAC file", 500)
			return
		}
		proxyAddr = net.JoinHostPort(proxyHost, strconv.Itoa(port))
		go runPerUserListener(user, client, port)
	}

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	fmt.Fprintf(w, pacTemplate, proxyAddr)
}

var pacTemplate = `function FindProxyForURL(url, host) {
	if (
		shExpMatch(url, "ftp:*") ||
		host == "localhost" ||
		isInNet(host, "127.0.0.0", "255.0.0.0") ||
		isInNet(host, "10.0.0.0", "255.0.0.0") ||
		isInNet(host, "172.16.0.0", "255.240.0.0") ||
		isInNet(host, "192.168.0.0", "255.255.0.0")
	) {
		return "DIRECT";
	}

	return "PROXY %s";
}`

func runPerUserListener(user string, clientIP string, port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Printf("error opening per-user listener for %s on port %d: %v", user, port, err)
		return
	}

	heartbeat := make(chan struct{})
	go func() {
		timeout := time.NewTimer(8 * time.Hour)
		for {
			select {
			case <-timeout.C:
				listener.Close()
				perUserPorts <- port
				timeout.Stop()
				return
			case <-heartbeat:
				timeout.Reset(8 * time.Hour)
			case <-shutdownChan:
				listener.Close()
				return
			}
		}
	}()

	handler := proxyHandler{user: user}
	server := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			heartbeat <- struct{}{}
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			if host != clientIP {
				http.Error(w, "Unauthorized IP address", http.StatusForbidden)
				return
			}
			handler.ServeHTTP(w, r)
		}),
	}

	err = server.Serve(listener)
	if err != nil && !strings.Contains(err.Error(), "use of closed") {
		log.Printf("Error running HTTP proxy for %s on port %d: %v", user, port, err)
	}
}
