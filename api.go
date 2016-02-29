package main

import "net/http"

var apiServeMux = http.NewServeMux()

func init() {
	apiServeMux.Handle("/debug/pprof/", http.DefaultServeMux)
	apiServeMux.HandleFunc("/proxy.pac", handlePACFile)
	apiServeMux.HandleFunc("/reload", handleReload)
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	apiServeMux.ServeHTTP(w, r)
}
