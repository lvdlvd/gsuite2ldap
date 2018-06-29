package main

import (
	"log"

	ldap "github.com/vjeantet/ldapserver"
)

func main() {

	server := ldap.NewServer()

	routes := ldap.NewRouteMux()
	routes.Bind(handleBind)
	routes.Extended(handleStartTLS).RequestName(ldap.NoticeOfStartTLS).Label("StartTLS")
	routes.Search(handleSearch).Label("Search")

	server.Handle(routes)

	log.Fatalln(server.ListenAndServe("127.0.0.1:10389"))
}

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	log.Printf("Request BaseDn=%s", r.BaseObject())
	log.Printf("Request Filter=%s", r.Filter())
	log.Printf("Request FilterString=%s", r.FilterString())
	log.Printf("Request Attributes=%s", r.Attributes())

	e := ldap.NewSearchResultEntry("cn=lvd, " + r.BaseObject())
	e.AddAttribute("cn", "lvd")
	e.AddAttribute("uid", "lvd")
	e.AddAttribute("uidNumber", "1000")
	e.AddAttribute("gidNumber", "1000")
	e.AddAttribute("homeDirectory", "/home/lvd")
	e.AddAttribute("objectClass", "posixAccount")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)

}
