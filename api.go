package main

import "net/http"

var apiServeMux = http.NewServeMux()

func init() {
	apiServeMux.Handle("/debug/pprof/", http.DefaultServeMux)
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	apiServeMux.ServeHTTP(w, r)
}
