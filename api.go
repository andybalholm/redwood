package main

import (
	"net/http"
)

var apiServeMux = http.NewServeMux()

func init() {
	apiServeMux.Handle("/debug/pprof/", http.DefaultServeMux)
	apiServeMux.HandleFunc("/proxy.pac", handlePACFile)
	apiServeMux.HandleFunc("/reload", handleReload)
	apiServeMux.HandleFunc("/classify", handleClassification)
	apiServeMux.HandleFunc("/classify/analyze-score", handleClassification)
	apiServeMux.HandleFunc("/classify/verbose", handleClassification)
	apiServeMux.HandleFunc("/classify-text", handleClassifyText)
	apiServeMux.HandleFunc("/classify-text/verbose", handleClassifyText)
	apiServeMux.HandleFunc("/analyze-tally", handleAnalyzeTally)

	apiServeMux.HandleFunc("/per-user-ports", handlePerUserPortList)
	apiServeMux.HandleFunc("/per-user-ports/authenticate", handlePerUserAuthenticate)
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	conf := getConfig()

	authUser := ""
	if user, pass, ok := r.BasicAuth(); ok {
		if conf.ValidCredentials(user, pass) {
			authUser = user
		} else {
			logAuthEvent("basic-auth", "invalid", r.RemoteAddr, 0, user, pass, "", "", r, "Incorrect username or password for API request")
		}
	}

	acls := conf.APIACLs.requestACLs(r, authUser)
	possibleActions := []string{"allow", "block"}
	if authUser == "" {
		possibleActions = append(possibleActions, "require-auth")
	}
	thisRule := conf.APIACLs.ChooseACLAction(acls, possibleActions...)

	switch thisRule.Action {
	case "require-auth":
		w.Header().Set("WWW-Authenticate", `Basic realm="Redwood API"`)
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		logAuthEvent("any-auth", "missing", r.RemoteAddr, 0, "", "", "", "", r, "Missing required API authentication")
		return

	case "block":
		http.Error(w, "You do not have access to this page.", http.StatusForbidden)
		return
	}

	apiServeMux.ServeHTTP(w, r)
}
