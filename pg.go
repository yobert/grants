package main

import (
	"crypto/md5"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx"
	"github.com/pkg/errors"
)

const (
	pgDefaultMarker = "*"
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
	RolPassword    *string
	RolValidUntil  *string
	//RolBypassRLS   bool // pg 10 thing
	RolConfig []string
}

type pgACL struct {
	Role    string
	Granter string
	Perms   []Perm
}

var pgConns = map[string]*pgx.Conn{}
var lastPrintedDB = "postgres"
var pgSafeIdent = regexp.MustCompile(`^[a-zA-Z]+[a-zA-Z0-9_]*$`)

func pgConn(dbname string) (*pgx.Conn, error) {

	config := baseconfig
	config.Database = dbname

	key := fmt.Sprintf("%s,%s,%s,%s", config.User, config.Host, config.Port, config.Database)

	c, ok := pgConns[key]
	if ok {
		return c, nil
	}

	defer timer(fmt.Sprintf("%#v connect user %#v host %#v", config.Database, config.User, config.Host)).done()

	var err error
	c, err = pgx.Connect(config)
	if err != nil {
		return nil, err
	}
	pgConns[key] = c
	return c, nil
}

func pgSelectExisting(defaultPrivRole string) (map[string]User, map[string]Database, error) {
	defer timer("total query").done()

	if baseconfig.Host == "none" {
		return nil, nil, nil
	}

	// Postgres is a little weird in now it splits out databases. We can query the database list,
	// but cannot query user permissions across databases from a single connection as far as I can tell.
	// So we loop through all the databases, and build up our data from there.

	out := map[string]User{}          // existing user and default permissions
	existing := map[string]Database{} // existing databases/schemas/tables/etc (so we can apply "*")

	conn, err := pgConn("postgres")
	if err != nil {
		return nil, nil, err
	}

	// Load every user (role). This list is the same no matter what database we connect to.

	sql := `select r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb,
                  r.rolcanlogin, r.rolreplication, r.rolconnlimit, s.passwd, r.rolvaliduntil,
                  r.rolconfig
           from pg_roles as r
           left join pg_shadow as s on
             r.rolname = s.usename;`

	rows, err := conn.Query(sql)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var r pgRole
		err := rows.Scan(
			&r.RolName, &r.RolSuper, &r.RolInherit, &r.RolCreateRole, &r.RolCreateDB,
			&r.RolCanLogin, &r.RolReplication, &r.RolConnLimit, &r.RolPassword, &r.RolValidUntil,
			&r.RolConfig,
		)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}
		if strings.ToLower(r.RolName) == "postgres" {
			continue
		}
		if strings.HasPrefix(r.RolName, "pg_") {
			continue
		}
		pass := ""
		if r.RolPassword != nil {
			pass = *r.RolPassword
		}
		grants := map[string]Perm{}
		if r.RolSuper {
			grants[Super.Name] = Super
		}
		if r.RolInherit {
			grants[Inherit.Name] = Inherit
		}
		if r.RolCreateRole {
			grants[CreateRole.Name] = CreateRole
		}
		if r.RolCanLogin {
			grants[Login.Name] = Login
		}
		settings := map[string]string{}
		for _, s := range r.RolConfig {
			i := strings.IndexByte(s, '=')
			if i == -1 {
				continue
			}
			k := s[:i]
			v := s[i+1:]
			settings[k] = v
		}

		out[r.RolName] = User{
			Name:     r.RolName,
			Password: pass,
			Grants:   grants,
			Valid:    true,
			Settings: settings,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, errors.WithStack(err)
	}

	// Now go through each database, loading all the table permissions

	var dbnames []string
	sql = `select datname, datacl from pg_catalog.pg_database;`

	rows, err = conn.Query(sql)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var (
			dbname string
			dbacl  []string
		)
		if err := rows.Scan(&dbname, &dbacl); err != nil {
			return nil, nil, errors.WithStack(err)
		}
		if dbname == "template0" {
			continue
		}
		dbnames = append(dbnames, dbname)

		existing[dbname] = Database{
			Name:    dbname,
			Schemas: map[string]Schema{},
		}

		for _, rule := range dbacl {
			acl, err := pgParseACL(rule, DatabasePerms)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "Database %#v ACL parse %#v", dbname, rule)
			}
			u, ok := out[acl.Role]
			if !ok {
				continue // skip permissions for users not in pg_roles (special users like postgres, pg_*, etc)
			}
			if u.Databases == nil {
				u.Databases = map[string]Database{}
			}
			d := u.Databases[dbname]
			d.Name = dbname
			if d.Grants == nil {
				d.Grants = map[string]Perm{}
			}
			for _, p := range acl.Perms {
				d.Grants[p.Name] = p
			}
			u.Databases[dbname] = d
			out[acl.Role] = u
		}

	}
	if err := rows.Err(); err != nil {
		return nil, nil, errors.WithStack(err)
	}

	for _, dbname := range dbnames {
		if err := pgSelectExistingSchemas(dbname, out, existing); err != nil {
			return nil, nil, err
		}
		if err := pgSelectExistingTableish(dbname, out, existing); err != nil {
			return nil, nil, err
		}
		if err := pgSelectExistingDefaults(defaultPrivRole, dbname, out); err != nil {
			return nil, nil, err
		}
	}
	return out, existing, nil
}

func pgSelectExistingSchemas(dbname string, out map[string]User, existing map[string]Database) error {
	defer timer(fmt.Sprintf("%#v query schema", dbname)).done()

	conn, err := pgConn(dbname)
	if err != nil {
		return err
	}

	sql := `select
		n.nspname,
		n.nspacl
from pg_catalog.pg_namespace as n;`

	type rowtype struct {
		schema string
		acl    []string
	}

	rows, err := conn.Query(sql)
	if err != nil {
		return errors.WithStack(err)
	}
	for rows.Next() {
		var r rowtype
		err := rows.Scan(&r.schema, &r.acl)
		if err != nil {
			return errors.WithStack(err)
		}

		schemaname := r.schema

		existing[dbname].Schemas[schemaname] = Schema{
			Name:      schemaname,
			Tables:    map[string]Table{},
			Sequences: map[string]Sequence{},
		}

		for _, rule := range r.acl {
			acl, err := pgParseACL(rule, SchemaPerms)
			if err != nil {
				return errors.Wrapf(err, "Schema %#v ACL parse %#v", schemaname, rule)
			}
			u, ok := out[acl.Role]
			if !ok {
				continue // skip permissions for users not in pg_roles (special users like postgres, pg_*, etc)
			}
			u.Name = acl.Role

			if u.Databases == nil {
				u.Databases = map[string]Database{}
			}
			d := out[acl.Role].Databases[dbname]
			d.Name = dbname
			if d.Schemas == nil {
				d.Schemas = map[string]Schema{}
			}
			s := d.Schemas[schemaname]
			s.Name = schemaname

			if s.Grants == nil {
				s.Grants = map[string]Perm{}
			}
			for _, p := range acl.Perms {
				s.Grants[p.Name] = p
			}
			d.Schemas[schemaname] = s
			u.Databases[dbname] = d
			out[acl.Role] = u
		}

	}
	if err := rows.Err(); err != nil {
		return errors.WithStack(err)
	}

	return nil
}
func pgSelectExistingTableish(dbname string, out map[string]User, existing map[string]Database) error {
	defer timer(fmt.Sprintf("%#v query table ACLs", dbname)).done()

	conn, err := pgConn(dbname)
	if err != nil {
		return err
	}

	sql := `select
		n.nspname,
		c.relname,
		c.relkind,
		c.relacl
	from pg_class as c
	left join pg_catalog.pg_namespace as n on
		n.oid = c.relnamespace
	where c.relkind in ('r', 'S');`

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
		if strings.HasPrefix(r.name, "pg_") || strings.HasPrefix(r.name, "sql_") {
			continue
		}

		schemaname := r.schema

		if r.kind == 'r' {
			existing[dbname].Schemas[schemaname].Tables[r.name] = Table{
				Name: r.name,
			}
		} else if r.kind == 'S' {
			existing[dbname].Schemas[schemaname].Sequences[r.name] = Sequence{
				Name: r.name,
			}
		}

		// table or sequence
		if r.kind == 'r' || r.kind == 'S' {
			for _, rule := range r.acl {
				acl, err := pgParseACL(rule, TablePerms, SequencePerms)
				if err != nil {
					return errors.Wrapf(err, "pg_class entry %#v ACL parse %#v", r.name, rule)
				}
				u, ok := out[acl.Role]
				if !ok {
					continue // skip permissions for users not in pg_roles (special users like postgres, pg_*, etc)
				}

				if u.Databases == nil {
					u.Databases = map[string]Database{}
				}
				d := u.Databases[dbname]
				d.Name = dbname
				if d.Schemas == nil {
					d.Schemas = map[string]Schema{}
				}
				s := d.Schemas[schemaname]
				s.Name = schemaname
				if r.kind == 'r' {
					tablename := r.name
					if s.Tables == nil {
						s.Tables = map[string]Table{}
					}
					t := s.Tables[tablename]
					if t.Grants == nil {
						t.Grants = map[string]Perm{}
					}
					for _, p := range acl.Perms {
						t.Grants[p.Name] = p
					}
					s.Tables[tablename] = t
				} else if r.kind == 'S' {
					sequencename := r.name
					if s.Sequences == nil {
						s.Sequences = map[string]Sequence{}
					}
					seq := s.Sequences[sequencename]
					if seq.Grants == nil {
						seq.Grants = map[string]Perm{}
					}
					for _, p := range acl.Perms {
						seq.Grants[p.Name] = p
					}
					s.Sequences[sequencename] = seq
				} else {
					return errors.Errorf("Unhandled access privilege kind %#v for role %#v", r.kind, acl.Role)
				}
				d.Schemas[schemaname] = s
				u.Databases[dbname] = d
				out[acl.Role] = u
			}
		}

	}
	if err := rows.Err(); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func pgSelectExistingDefaults(defaultPrivRole string, dbname string, out map[string]User) error {
	defer timer(fmt.Sprintf("%#v query defualt ACL", dbname)).done()

	conn, err := pgConn(dbname)
	if err != nil {
		return err
	}

	sql := `select
		r.rolname,
		n.nspname,
		d.defaclobjtype,
		d.defaclacl
from pg_catalog.pg_default_acl as d
left join pg_catalog.pg_roles as r on
	r.oid = d.defaclrole
left join pg_catalog.pg_namespace as n on
	n.oid = d.defaclnamespace
where
	d.defaclobjtype in ('r', 'S');`

	type rowtype struct {
		name   string
		schema string
		kind   rune
		acl    []string
	}

	rows, err := conn.Query(sql)
	if err != nil {
		return errors.WithStack(err)
	}
	for rows.Next() {
		var r rowtype
		err := rows.Scan(&r.name, &r.schema, &r.kind, &r.acl)
		if err != nil {
			return errors.WithStack(err)
		}

		// For now, we're only going to manage default rules for a single user (postgres).
		// I'm not sure how to squish multi-user into the input syntax yet.
		// This means that default permissions will only work if postgres is the user creating things,
		// which I think is a pretty safe assumption for now.
		if r.name != defaultPrivRole {
			continue
		}

		schemaname := r.schema

		// table or sequence
		if r.kind == 'r' || r.kind == 'S' {
			for _, rule := range r.acl {
				acl, err := pgParseACL(rule, TablePerms, SequencePerms)
				if err != nil {
					return errors.Wrapf(err, "default acl %#v kind %#v ACL parse %#v", r.schema, r.kind, rule)
				}
				u, ok := out[acl.Role]
				if !ok {
					continue // skip permissions for users not in pg_roles (special users like postgres, pg_*, etc)
				}

				if u.Databases == nil {
					u.Databases = map[string]Database{}
				}
				d := u.Databases[dbname]
				d.Name = dbname
				if d.Schemas == nil {
					d.Schemas = map[string]Schema{}
				}
				s := d.Schemas[schemaname]
				s.Name = schemaname
				if r.kind == 'r' {
					tablename := pgDefaultMarker
					if s.Tables == nil {
						s.Tables = map[string]Table{}
					}
					t := s.Tables[tablename]
					if t.Grants == nil {
						t.Grants = map[string]Perm{}
					}
					for _, p := range acl.Perms {
						t.Grants[p.Name] = p
					}
					s.Tables[tablename] = t
				} else if r.kind == 'S' {
					sequencename := pgDefaultMarker
					if s.Sequences == nil {
						s.Sequences = map[string]Sequence{}
					}
					seq := s.Sequences[sequencename]
					if seq.Grants == nil {
						seq.Grants = map[string]Perm{}
					}
					for _, p := range acl.Perms {
						seq.Grants[p.Name] = p
					}
					s.Sequences[sequencename] = seq
				} else {
					return errors.Errorf("Unhandled default access privilege kind %#v for role %#v", r.kind, acl.Role)
				}
				d.Schemas[schemaname] = s
				u.Databases[dbname] = d
				out[acl.Role] = u
			}
		}

	}
	if err := rows.Err(); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func pgParseACL(input string, permlist ...[]Perm) (pgACL, error) {
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
chars:
	for _, ch := range chunks[1] {
		for _, p := range permlist {
			for _, pp := range p {
				if pp.Pg == string(ch) {
					r.Perms = append(r.Perms, pp)
					continue chars
				}
			}
		}
		return r, errors.Errorf("Unhandled privilege character %#v", string(ch))
	}
	return r, nil
}

func pgPasswordHash(user, pw string) string {
	if pw == "" {
		return pw
	}
	if len(pw) == 35 && strings.HasPrefix(pw, "md5") {
		return pw
	}
	return fmt.Sprintf("md5%x", md5.Sum([]byte(pw+user)))
}

var pgHolderRe = regexp.MustCompile(`\$\d+`)

func pgReplace(sql string, params []interface{}) string {
	return pgHolderRe.ReplaceAllStringFunc(sql, func(s string) string {
		i, err := strconv.Atoi(s[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "placeholder %#v parse error: %v\n", s, err)
			return s
		}
		i--
		if i < 0 || i+1 > len(params) {
			fmt.Fprintf(os.Stderr, "placeholder %#v out of range\n", s)
			return s
		}
		v := params[i]
		switch vv := v.(type) {
		case nil:
			return "null"
		case string:
			return pgQuote(vv)
		case int:
			return strconv.Itoa(vv)
		default:
			fmt.Fprintf(os.Stderr, "placeholder %#v has unhandled type %T\n", s, v)
			return s
		}
	})
}

func pgQuote(str string) string {
	return "'" + strings.Replace(str, "'", "''", -1) + "'"
}
func pgQuoteIdent(str string) string {
	if pgSafeIdent.MatchString(str) {
		return str
	}
	return "\"" + strings.Replace(str, "\"", "\"\"", -1) + "\""
}
func pgQuoteIdentPair(a, b string) string {
	return pgQuoteIdent(a) + "." + pgQuoteIdent(b)
}

func pgExecMain(sql string, args ...interface{}) error {
	return pgExec("postgres", sql, args...)
}
func pgExec(db string, sql string, args ...interface{}) error {
	defer timer(fmt.Sprintf("%#v %s", db, pgReplace(sql, args))).done()

	if db != lastPrintedDB && !quiet && !timing {
		fmt.Println("\\connect " + pgQuoteIdent(db))
		lastPrintedDB = db
	}

	if !timing && !quiet {
		fmt.Println(pgReplace(sql, args))
	}

	if dry {
		return nil
	}

	conn, err := pgConn(db)
	if err != nil {
		return err
	}

	_, err = conn.Exec(sql, args...)
	return err
}
