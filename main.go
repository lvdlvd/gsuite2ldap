package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/nmcclain/ldap"
)

var (
	port    = flag.String("ldap", "localhost:10389", "Port to serve ldap on.")
	uidBase = flag.Int("uidbase", 2000, "add this to the gsuite employee numbers to create UID/GID number")
)

func main() {
	flag.Parse()

	s := ldap.NewServer()
	s.EnforceLDAP = true

	srv := getClient()
	uu, err := listUsers(srv)
	if err != nil {
		log.Fatalln(err)
	}

	// register Bind and Search function handlers
	handler := ldapHandler{uu}

	s.BindFunc("", &handler)
	s.SearchFunc("", &handler)

	// start the server
	log.Printf("Starting LDAP server on %s", *port)
	log.Fatalln(s.ListenAndServe(*port))
}

type ldapHandler struct {
	users map[int]string
}

func (h *ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	if bindDN == "" && bindSimplePw == "" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}

func (h *ldapHandler) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {

	objcls, err := ldap.GetFilterObjectClass(searchReq.Filter)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInvalidDNSyntax}, err
	}

	entries := []*ldap.Entry{}

	// restore capitalisation
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
		for uid, name := range h.users {
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
