package main

import (
	"fmt"
)

type User struct {
	Name     string
	Password string

	// database -> table -> perm name -> perm
	Grants map[string]map[string]map[string]Perm

	// user-level permissions such as SUPER and LOGIN
	Perms map[string]Perm
}

func (u User) Print() {
	fmt.Printf("user %#v password %#v\n", u.Name, u.Password)
	for _, p := range u.Perms {
		fmt.Println("\t» " + p.Name)
	}
	for dbname, tables := range u.Grants {
		fmt.Println("\t" + dbname)
		for tablename, grants := range tables {
			fmt.Println("\t\t" + tablename)
			for _, perm := range grants {
				fmt.Println("\t\t\t" + perm.String())
			}
		}
	}
}
