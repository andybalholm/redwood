package main

import "strings"

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
	"Darwin",
	"Windows",
	"Blackberry",
	"MAC",
	"Mac",
	"Microsoft",
	"MICROSOFT",
	"WIN",
	"Win",
	"GoogleAuth",
	"okhttp",
	"CaptiveNetworkSupport",
	"MobileAsset",
}

var platformAliases = map[string]string{
	"MAC":                   "Macintosh",
	"Mac":                   "Macintosh",
	"MICROSOFT":             "Windows",
	"Microsoft":             "Windows",
	"WIN":                   "Windows",
	"Win":                   "Windows",
	"GoogleAuth":            "Android",
	"okhttp":                "Android",
	"CaptiveNetworkSupport": "Darwin",
	"MobileAsset":           "Darwin",
}

var darwinPlatforms = map[string]bool{
	"Macintosh": true,
	"iPhone":    true,
	"iPad":      true,
	"iPod":      true,
	"Darwin":    true,
}

// platform examines a User-Agent string and attempts to return
// the platform that the client is running on. If it can't detect the platform,
// it returns the empty string. Apple products are distinguished if possible
// (Macintosh, iPad, etc.), but often will be just Darwin.
func platform(ua string) string {
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
