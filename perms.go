package main

import (
	"strings"
)

type Perm struct {
	Name string

	Pg string
}

var (
	Super      = Perm{Name: "SUPERUSER"}
	Login      = Perm{Name: "LOGIN"}
	Inherit    = Perm{Name: "INHERIT"}
	CreateRole = Perm{Name: "CREATEROLE"}
	CreateDB   = Perm{Name: "CREATEDB"}
	UserPerms  = []Perm{
		Super,
		Inherit,
		CreateRole,
		CreateDB,
		Login,
	}

	Connect       = Perm{Name: "CONNECT", Pg: "c"}
	DatabasePerms = []Perm{
		Connect,
		Create,
		Temporary,
	}

	Execute     = Perm{Name: "EXECUTE", Pg: "X"}
	Usage       = Perm{Name: "USAGE", Pg: "U"}
	Create      = Perm{Name: "CREATE", Pg: "C"}
	Temporary   = Perm{Name: "TEMPORARY", Pg: "T"}
	SchemaPerms = []Perm{
		Execute,
		Usage,
		Create,
		Temporary,
	}

	Select     = Perm{Name: "SELECT", Pg: "r"}
	Update     = Perm{Name: "UPDATE", Pg: "w"}
	Insert     = Perm{Name: "INSERT", Pg: "a"}
	Delete     = Perm{Name: "DELETE", Pg: "d"}
	Truncate   = Perm{Name: "TRUNCATE", Pg: "D"}
	References = Perm{Name: "REFERENCES", Pg: "x"}
	Trigger    = Perm{Name: "TRIGGER", Pg: "t"}
	Maintain   = Perm{Name: "MAINTAIN", Pg: "m"}
	TablePerms = []Perm{
		Select,
		Update,
		Insert,
		Delete,
		Truncate,
		References,
		Trigger,
		Maintain,
	}

	SequencePerms = []Perm{
		Usage,
		Select,
		Update,
	}

	DefaultNewUserPerms = []Perm{
		Inherit,
	}

	//Star       = Perm{Name: "STAR", Pg: "*"}
)

func (p Perm) String() string {
	return p.Name
}

func permCanonical(in string) string {
	return strings.TrimSpace(strings.ToUpper(in))
}
