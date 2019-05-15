package main

import (
	"fmt"
)

type User struct {
	Name      string
	Password  string
	Grants    Grants
	Databases map[string]Database
	Settings  map[string]string
	Valid     bool
}
type Database struct {
	Name    string
	Grants  Grants
	Schemas map[string]Schema
}
type Schema struct {
	Name      string
	Grants    Grants
	Tables    map[string]Table
	Sequences map[string]Sequence
}
type Table struct {
	Name   string
	Grants Grants
	// later: columns
}
type Sequence struct {
	Name   string
	Grants Grants
}
type Grants map[string]Perm

func (u User) Print() {
	fmt.Printf("user %#v password %#v settings %#v\n", u.Name, u.Password, u.Settings)
	for _, p := range u.Grants {
		fmt.Println("\t» " + p.Name)
	}
	for dbname, db := range u.Databases {
		fmt.Println("\t" + dbname)
		for _, p := range db.Grants {
			fmt.Println("\t» " + p.Name)
		}
		for schemaname, schema := range db.Schemas {
			fmt.Println("\t\t" + schemaname)
			for _, p := range schema.Grants {
				fmt.Println("\t\t» " + p.Name)
			}
			for tablename, table := range schema.Tables {
				fmt.Println("\t\t\t" + tablename)
				for _, p := range table.Grants {
					fmt.Println("\t\t\t» " + p.Name)
				}
			}
		}
	}
}
