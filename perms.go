package main

type Perm struct {
	Name string

	Pg string
}

var (
	Select     = Perm{Name: "SELECT", Pg: "r"}
	Update     = Perm{Name: "UPDATE", Pg: "w"}
	Insert     = Perm{Name: "INSERT", Pg: "a"}
	Delete     = Perm{Name: "DELETE", Pg: "d"}
	Truncate   = Perm{Name: "TRUNCATE", Pg: "D"}
	References = Perm{Name: "REFERENCES", Pg: "x"}
	Trigger    = Perm{Name: "TRIGGER", Pg: "t"}
	Execute    = Perm{Name: "EXECUTE", Pg: "X"}
	Usage      = Perm{Name: "USAGE", Pg: "U"}
	Create     = Perm{Name: "CREATE", Pg: "C"}
	Connect    = Perm{Name: "CONNECT", Pg: "c"}
	Temporary  = Perm{Name: "TEMPORARY", Pg: "T"}
	Star       = Perm{Name: "STAR", Pg: "*"}

	Perms = [...]Perm{
		Select,
		Update,
		Insert,
		Delete,
		Truncate,
		References,
		Trigger,
	}

	Super = Perm{Name: "SUPERUSER"}
	Login = Perm{Name: "LOGIN"}

	UserPerms = [...]Perm{
		Super,
		Login,
	}
)

func (p Perm) String() string {
	return p.Name
}
