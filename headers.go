package main

import (
	"net/http"
	"strings"
)

// platformStrings is a list of platform names to look for in User-Agent
// strings. The order matters; the first one found will be considered the
// correct result.
var platformStrings = []string{
	"Android",
	"Linux",
	"Macintosh",
	"iPad",
	"iPod",
	"iPhone",
	"iOS",
	"Darwin",
	"dataaccessd",
	"Windows",
	"Blackberry",
	"BlackBerry",
	"BB10",
	"MAC",
	"Mac",
	"Microsoft",
	"MICROSOFT",
	"MS Web Service",
	"WIN",
	"Win",
	"GoogleAuth",
	"Gms-Backup",
	"GmsCore",
	"okhttp",
	"CaptiveNetworkSupport",
	"CloudKit",
	"CFNetwork",
	"com.apple",
}

var platformAliases = map[string]string{
	"BB10":                  "Blackberry",
	"BlackBerry":            "Blackberry",
	"MAC":                   "Macintosh",
	"Mac":                   "Macintosh",
	"macOS":                 "Macintosh",
	"MICROSOFT":             "Windows",
	"Microsoft":             "Windows",
	"MS Web Service":        "Windows",
	"WIN":                   "Windows",
	"Win":                   "Windows",
	"GoogleAuth":            "Android",
	"Gms-Backup":            "Android",
	"Gms-Core":              "Android",
	"okhttp":                "Android",
	"CaptiveNetworkSupport": "Darwin",
	"CloudKit":              "Darwin",
	"CFNetwork":             "Darwin",
	"dataaccessd":           "Darwin",
	"iOS":                   "Darwin",
	"com.apple":             "Darwin",
	"Chrome OS":             "Linux",
	"Chromium OS":           "Linux",
}

var darwinPlatforms = map[string]bool{
	"Macintosh": true,
	"iPhone":    true,
	"iPad":      true,
	"iPod":      true,
	"Darwin":    true,
}

// platform examines a Sec-CH-UA-Platform or User-Agent string and attempts to return
// the platform that the client is running on. If it can't detect the platform,
// it returns the empty string. Apple products are distinguished if possible
// (Macintosh, iPad, etc.), but often will be just Darwin.
func platform(header http.Header) string {

	chPlatform := platformFromClientHint(header.Get("Sec-CH-UA-Platform"))

	// If the UA value is "iOS", check the UA string, to
	// determine the form factor (iPhone, iPad, iPod).
	if chPlatform != "" && chPlatform != "iOS" {
		return chPlatform
	}

	if uaPlatform := platformFromUA(header.Get("User-Agent")); uaPlatform != "" {
		return uaPlatform
	}

	return chPlatform

}

// platformFromClientHint examines a Sec-CH-UA-Platform string for platform value.
// If the header is not present or is "Unknown", fall back to parsing the User-Agent string.
func platformFromClientHint(ch string) string {
	if ch == "" {
		return ""
	}

	ch = strings.Trim(ch, `"`)
	if ch == "Unknown" {
		return ""
	}

	if chAlias, ok := platformAliases[ch]; ok {
		return chAlias
	}

	return ch
}

// platformFromUA examines a User-Agent string and attempts to return
// the platform that the client is running on. If it can't detect the platform,
// it returns the empty string. Apple products are distinguished if possible
// (Macintosh, iPad, etc.), but often will be just Darwin.
func platformFromUA(ua string) string {
	if ua == "" {
		return ""
	}
	for _, p := range platformStrings {
		if strings.Contains(ua, p) {
			if p2, ok := platformAliases[p]; ok {
				p = p2
			}
			return p
		}
	}

	return ""
}
