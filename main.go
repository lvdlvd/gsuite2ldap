package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/api/admin/directory/v1"

	"github.com/nmcclain/ldap"
)

var (
	port     = flag.String("ldap", "localhost:10389", "Port to serve ldap on.")
	uidBase  = flag.Int("uidbase", 2000, "add this to the gsuite employee numbers to create UID/GID number")
	certFile = flag.String("cert", "", "path to certfile")
	keyFile  = flag.String("key", "", "path to private key file.  if not absolute, relative to certfile's directory")
)

func main() {
	flag.Parse()

	if *keyFile != "" && filepath.Dir(*keyFile) == "." {
		*keyFile = filepath.Join(filepath.Dir(*certFile), filepath.Base(*keyFile))
	}

	s := ldap.NewServer()
	s.EnforceLDAP = true

	handler := ldapHandler{svr: getClient()}
	handler.reload()
	go func() {
		for _ = range time.Tick(300 * time.Second) {
			handler.reload()
		}
	}()

	s.BindFunc("", &handler)
	s.SearchFunc("", &handler)

	// start the server
	if *keyFile != "" {
		log.Printf("Starting LDAP TLS server on %s", *port)
		log.Printf("keyfile : %s", *keyFile)
		log.Printf("certfile: %s", *certFile)
		log.Fatalln(s.ListenAndServeTLS(*port, *certFile, *keyFile))
	}

	log.Printf("Starting LDAP server on %s", *port)
	log.Fatalln(s.ListenAndServe(*port))
}

type ldapHandler struct {
	sync.Mutex
	svr   *admin.Service
	users map[int]string
}

// todo: reload if we are queried and have zero results and its been more than 1 minute since we reloaded
func (h *ldapHandler) reload() {
	uu, err := listUsers(h.svr)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("found %d users", len(uu))
	h.Lock()
	h.users = uu
	h.Unlock()
}

func (h *ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	if bindDN == "" && bindSimplePw == "" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}

// todo: parse and apply filter here and if no matches, trigger search (if older than 1 minute)
func (h *ldapHandler) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {

	objcls, err := ldap.GetFilterObjectClass(searchReq.Filter)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
	}

	entries := []*ldap.Entry{}

	h.Lock()
	defer h.Unlock()

	switch objcls {
	case "posixaccount":
		for uid, name := range h.users {
			entries = append(entries, &ldap.Entry{DN: fmt.Sprintf("cn=%s,%s", name, searchReq.BaseDN), Attributes: []*ldap.EntryAttribute{
				&ldap.EntryAttribute{"cn", []string{name}},
				&ldap.EntryAttribute{"uid", []string{name}},
				&ldap.EntryAttribute{"uidNumber", []string{fmt.Sprintf("%d", *uidBase+uid)}},
				&ldap.EntryAttribute{"gidNumber", []string{fmt.Sprintf("%d", *uidBase+uid)}},
				&ldap.EntryAttribute{"homeDirectory", []string{fmt.Sprintf("/home/%s", name)}},
				&ldap.EntryAttribute{"objectClass", []string{"top", "posixAccount"}},
			}})
		}

	case "shadowaccount":
		for _, name := range h.users {
			entries = append(entries, &ldap.Entry{DN: fmt.Sprintf("cn=%s,%s", name, searchReq.BaseDN), Attributes: []*ldap.EntryAttribute{
				&ldap.EntryAttribute{"uid", []string{name}},
				&ldap.EntryAttribute{"objectClass", []string{"top", "shadowAccount"}},
			}})
		}

	case "posixgroup":
		for uid, name := range h.users {
			entries = append(entries, &ldap.Entry{DN: fmt.Sprintf("cn=%s,%s", name, searchReq.BaseDN), Attributes: []*ldap.EntryAttribute{
				&ldap.EntryAttribute{"cn", []string{name}},
				&ldap.EntryAttribute{"gidNumber", []string{fmt.Sprintf("%d", *uidBase+uid)}},
				&ldap.EntryAttribute{"objectClass", []string{"top", "posixGroup"}},
			}})
		}

	default:
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultNoSuchObject}, nil
	}

	return ldap.ServerSearchResult{entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}
