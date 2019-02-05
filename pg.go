package main

import (
	"strings"

	"github.com/jackc/pgx"
	"github.com/pkg/errors"
)

type pgRole struct {
	RolName        string
	RolSuper       bool
	RolInherit     bool
	RolCreateRole  bool
	RolCreateDB    bool
	RolCanLogin    bool
	RolReplication bool
	RolConnLimit   int
	RolPassword    string
	RolValidUntil  *string
	RolBypassRLS   bool
	RolConfig      []string
}

type pgACL struct {
	Role    string
	Granter string

	Select     bool
	Update     bool
	Insert     bool
	Delete     bool
	Truncate   bool
	References bool
	Trigger    bool
	Execute    bool
	Usage      bool
	Create     bool
	Connect    bool
	Temporary  bool
	Star       bool
}

func pgSelectExisting() (map[string]User, error) {
	defer timer("select existing grants").done()

	// Postgres is a little weird in now it splits out databases. We can query the database list,
	// but cannot query user permissions across databases from a single connection as far as I can tell.
	// So we loop through all the databases, and build up our data from there.

	out := map[string]User{}

	config := pgx.ConnConfig{
		User:     "postgres",
		Database: "postgres",
	}

	conn, err := pgx.Connect(config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Load every user (role). This list is the same no matter what database we connect to.

	sql := `select rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb,
                  rolcanlogin, rolreplication, rolconnlimit, rolpassword, rolvaliduntil,
                  rolbypassrls, rolconfig
           from pg_roles;`

	rows, err := conn.Query(sql)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r pgRole
		err := rows.Scan(
			&r.RolName, &r.RolSuper, &r.RolInherit, &r.RolCreateRole, &r.RolCreateDB,
			&r.RolCanLogin, &r.RolReplication, &r.RolConnLimit, &r.RolPassword, &r.RolValidUntil,
			&r.RolBypassRLS, &r.RolConfig,
		)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		if strings.HasPrefix(r.RolName, "pg_") {
			continue
		}
		out[r.RolName] = User{
			Name:   r.RolName,
			Grants: map[string]map[string]Grants{},
			Super:  r.RolSuper,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.WithStack(err)
	}

	// Now go through each database, loading all the table permissions

	sql = `select datname from pg_catalog.pg_database;`

	rows, err = conn.Query(sql)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var dbname string
		if err := rows.Scan(&dbname); err != nil {
			return nil, errors.WithStack(err)
		}
		if dbname == "template0" {
			continue
		}

		err := pgSelectExistingDB(config, dbname, out)
		if err != nil {
			return nil, err
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	return out, nil
}

func pgSelectExistingDB(config pgx.ConnConfig, dbname string, out map[string]User) error {
	config.Database = dbname

	conn, err := pgx.Connect(config)
	if err != nil {
		return errors.WithStack(err)
	}
	defer conn.Close()

	sql := `select
		n.nspname,
		c.relname,
		c.relkind,
		c.relacl
	from pg_class as c
	left join pg_catalog.pg_namespace as n on
		n.oid = c.relnamespace
	where c.relkind in ('r', 'S', 'v', 'm');`

	type rowtype struct {
		schema string
		name   string
		kind   rune
		acl    []string
	}

	rows, err := conn.Query(sql)
	if err != nil {
		return errors.WithStack(err)
	}
	for rows.Next() {
		var r rowtype
		err := rows.Scan(&r.schema, &r.name, &r.kind, &r.acl)
		if err != nil {
			return errors.WithStack(err)
		}
		// for now just look at tables
		if r.kind != 'r' {
			continue
		}
		if strings.HasPrefix(r.name, "pg_") || strings.HasPrefix(r.name, "sql_") {
			continue
		}
		for _, rule := range r.acl {
			acl, err := pgParseACL(rule)
			if err != nil {
				return errors.Wrapf(err, "ACL parse %#v", rule)
			}
			_, ok := out[acl.Role]
			if !ok {
				// skip permissions for users not in pg_roles
				continue
			}
			if out[acl.Role].Grants[dbname] == nil {
				out[acl.Role].Grants[dbname] = map[string]Grants{}
			}
			g := out[acl.Role].Grants[dbname][r.name]
			if acl.Select {
				g.Select = true
			}
			out[acl.Role].Grants[dbname][r.name] = g
		}
	}
	if err := rows.Err(); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func pgParseACL(input string) (pgACL, error) {
	var r pgACL

	chunks := strings.Split(input, "/")
	if len(chunks) != 2 {
		return r, errors.New("Expected one forward slash")
	}
	r.Granter = chunks[1]
	chunks = strings.Split(chunks[0], "=")
	if len(chunks) != 2 {
		return r, errors.New("Expected one equals sign")
	}
	r.Role = chunks[0]
	if r.Role == "" {
		r.Role = "*"
	}

	for _, ch := range chunks[1] {
		switch ch {
		case 'r':
			r.Select = true
		case 'w':
			r.Update = true
		case 'a':
			r.Insert = true
		case 'd':
			r.Delete = true
		case 'D':
			r.Truncate = true
		case 'x':
			r.References = true
		case 't':
			r.Trigger = true
		case 'X':
			r.Execute = true
		case 'U':
			r.Usage = true
		case 'C':
			r.Create = true
		case 'c':
			r.Connect = true
		case 'T':
			r.Temporary = true
		case '*':
			r.Star = true
		default:
			return r, errors.Errorf("Unhandled privilege character %#v", ch)
		}
	}
	return r, nil
}
