include $(GOROOT)/src/Make.inc

TARG=redwood
GOFILES=\
	blockpage.go\
	categories.go\
	config.go\
	mapsort.go\
	phrase.go\
	phrase_scan.go\
	redwood.go\
	reqmod.go\
	respmod.go\
	testmode.go\
	url.go\
	word.go\

include $(GOROOT)/src/Make.cmd

