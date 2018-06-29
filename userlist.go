// +build ignore

// test lisusers by doing
//  go run userlist.go listuser.go

package main

import "log"

func main() {
	srv := getClient()
	uu, err := listUsers(srv)
	if err != nil {
		log.Fatalln(err)
	}
	for k, v := range uu {
		log.Println(k, v)
	}
}
