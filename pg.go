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
	RolBypassRLS   bool
	RolConfig      []string
}

type pgACL struct {
	Role    string
	Granter string
	Perms   []Perm
}

var pgConns = map[string]*pgx.Conn{}
var lastPrintedDB = "postgres"

func pgConn(config pgx.ConnConfig) (*pgx.Conn, error) {
	key := fmt.Sprintf("%s/%s/%s", config.User, config.Host, config.Database)

	c, ok := pgConns[key]
	if ok {
		return c, nil
	}
	var err error
	c, err = pgx.Connect(config)
	if err != nil {
		return nil, err
	}
	pgConns[key] = c
	return c, nil
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

	conn, err := pgConn(config)
	if err != nil {
		return nil, err
	}

	// Load every user (role). This list is the same no matter what database we connect to.

	sql := `select r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb,
                  r.rolcanlogin, r.rolreplication, r.rolconnlimit, s.passwd, r.rolvaliduntil,
                  r.rolbypassrls, r.rolconfig
           from pg_roles as r
           left join pg_shadow as s on
             r.rolname = s.usename;`

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
		pass := ""
		if r.RolPassword != nil {
			pass = *r.RolPassword
		}
		perms := map[string]Perm{}
		if r.RolSuper {
			perms[Super.Name] = Super
		}
		if r.RolCanLogin {
			perms[Login.Name] = Login
		}
		out[r.RolName] = User{
			Name:     r.RolName,
			Password: pass,
			Grants:   map[string]map[string]map[string]Perm{},
			Perms:    perms,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.WithStack(err)
	}

	// Now go through each database, loading all the table permissions

	var dbnames []string
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
		dbnames = append(dbnames, dbname)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.WithStack(err)
	}

	for _, dbname := range dbnames {
		err := pgSelectExistingDB(config, dbname, out)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func pgSelectExistingDB(config pgx.ConnConfig, dbname string, out map[string]User) error {
	config.Database = dbname

	conn, err := pgConn(config)
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
				out[acl.Role].Grants[dbname] = map[string]map[string]Perm{}
			}
			if out[acl.Role].Grants[dbname][r.name] == nil {
				out[acl.Role].Grants[dbname][r.name] = map[string]Perm{}
			}
			for _, p := range acl.Perms {
				out[acl.Role].Grants[dbname][r.name][p.Name] = p
			}
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

chars:
	for _, ch := range chunks[1] {
		for _, p := range Perms {
			if p.Pg == string(ch) {
				r.Perms = append(r.Perms, p)
				continue chars
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

func pgExecMain(sql string, args ...interface{}) error {
	return pgExec("postgres", sql, args...)
}
func pgExec(db string, sql string, args ...interface{}) error {

	if db != lastPrintedDB {
		fmt.Println("-- database " + db)
		lastPrintedDB = db
	}
	fmt.Println(pgReplace(sql, args))

	if dry {
		return nil
	}

	config := pgx.ConnConfig{
		User:     "postgres",
		Database: db,
	}

	conn, err := pgConn(config)
	if err != nil {
		return err
	}

	_, err = conn.Exec(sql, args...)
	return err
}
