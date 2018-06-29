// see https://developers.google.com/admin-sdk/directory/v1/quickstart/go
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/admin/directory/v1"
)

type userInfo struct {
	Name string
	Uid  int
}

func main() {
	// client, err := google.DefaultClient(context.Background(), admin.AdminDirectoryUserReadonlyScope)
	// if err != nil {
	// 	log.Fatal("failed to create client")
	// }
	// srv, err := admin.New(client)
	// if err != nil {
	// 	log.Fatal("failed to create service")
	// }

	srv := getClient()
	uu, err := listUsers(srv)
	log.Println(err)
	for _, v := range uu {
		log.Println(v)
	}

	u2n := map[int][]string{}
	for _, v := range uu {
		u2n[v.Uid] = append(u2n[v.Uid], v.Name)
	}
	for k, v := range u2n {
		if len(v) > 1 {
			log.Printf("UID %d maps to multiple users: %v", k, v)
		}
	}

}

func listUsers(srv *admin.Service) ([]userInfo, error) {

	req := srv.Users.List()
	req = req.Customer("my_customer")
	//req = req.Domain("example.org")

	r, err := req.Do()
	if err != nil {
		return nil, err
	}

	var uu []userInfo
users:
	for _, u := range r.Users {
		//fmt.Printf("%#v\n", u)
		if u.Suspended {
			continue
		}

		// ExternalIds is an interface{} that contains an []interface{} that has map[string]interface{} elements.
		// fragile but we'll notice when it changes b/c no uids come back.
		list, _ := u.ExternalIds.([]interface{})
		for _, v := range list {
			m, ok := v.(map[string]interface{})
			if !ok {
				continue
			}
			if s, _ := m["type"].(string); s != "organization" {
				continue
			}
			s, _ := m["value"].(string)
			n, err := strconv.ParseInt(s, 10, 32)
			if err != nil {
				continue
			}
			uu = append(uu, userInfo{Name: strings.Split(u.PrimaryEmail, "@")[0], Uid: int(n)})
			continue users
		}

		log.Printf("No uid found for %q", u.PrimaryEmail)
	}

	return uu, nil

}

func homeDir() string {
	usr, err := user.Current()
	if err != nil {
		log.Fatalln(err)
	}
	return usr.HomeDir
}

// getTokenFromWeb uses Config to request a Token.
// It returns the retrieved Token.
func tokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	log.Printf("Go to the following link in your browser then type the authorization code: \n%v\n", authURL)

	var code string
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatalf("Unable to read authorization code %v", err)
	}

	tok, err := config.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web %v", err)
	}
	return tok
}

// tokenFromFile retrieves a Token from a given file path.
// It returns the retrieved Token and any read error encountered.
func loadToken(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	t := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(t)
	return t, err
}

// saveToken uses a file path to create a file and store the
// token in it.
func saveToken(file string, token *oauth2.Token) {
	log.Printf("Saving credential file to: %s\n", file)
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

// getClient uses a Context and Config to retrieve a Token
// then generate a Client. It returns the generated Client.
func getClient() *admin.Service {

	home := homeDir()
	basename := filepath.Base(os.Args[0])

	cs, err := ioutil.ReadFile(filepath.Join(filepath.Dir(os.Args[0]), "client_secret.json"))
	if err != nil {
		cs, err = ioutil.ReadFile(filepath.Join(home, ".credentials", "client_secret.json"))
	}
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	config, err := google.ConfigFromJSON(cs, admin.AdminDirectoryUserReadonlyScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}

	tokenCacheDir := filepath.Join(home, ".credentials")
	cacheFile := filepath.Join(tokenCacheDir, basename+".json")
	tok, err := loadToken(cacheFile)
	if err != nil {
		os.MkdirAll(tokenCacheDir, 0700)
		tok = tokenFromWeb(config)
		saveToken(cacheFile, tok)
	}

	srv, err := admin.New(config.Client(context.Background(), tok))
	if err != nil {
		log.Fatalf("Unable to construct calendar Client %v", err)
	}
	return srv
}
