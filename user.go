package main

import (
	"fmt"
	"strings"
)

type User struct {
	Name     string
	Password string

	Grants map[string]map[string]Grants

	Super bool
}

type Grants struct {
	Select bool
}

func (u User) String() string {
	attrs := []string{}
	if u.Super {
		attrs = append(attrs, "superuser")
	}

	attrstr := ""
	if len(attrs) > 0 {
		attrstr = " (" + strings.Join(attrs, ", ") + ")"
	}
	return fmt.Sprintf("%s%s", u.Name, attrstr)
}

func (g Grants) String() string {
	list := []string{}
	if g.Select {
		list = append(list, "SELECT")
	}
	return strings.Join(list, ", ")
}
