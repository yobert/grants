package main

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
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
	RolValidUntil  pgtype.Timestamptz
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

var ignoreDatabases = map[string]bool{
	"rdsadmin":  true,
	"template0": true,
}
var ignoreUsers = map[string]bool{
	"postgres": true,
}

func pgConn(dbname string) (*pgx.Conn, error) {

	ctx := context.Background()

	config := baseconfig
	config.Database = dbname

	key := fmt.Sprintf("%s,%s,%d,%s", config.User, config.Host, config.Port, config.Database)

	c, ok := pgConns[key]
	if ok {
		return c, nil
	}

	defer timer(fmt.Sprintf("%#v connect user %#v host %#v", config.Database, config.User, config.Host)).done()

	var err error
	c, err = pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	pgConns[key] = c
	return c, nil
}

func pgSelectExisting(defaultPrivRole string) (map[string]User, map[string]Database, error) {
	defer timer("total query").done()

	ctx := context.Background()

	// Postgres is a little weird in now it splits out databases. We can query the database list,
	// but cannot query user permissions across databases from a single connection as far as I can tell.
	// So we loop through all the databases, and build up our data from there.

	out := map[string]User{}          // existing user and default permissions
	existing := map[string]Database{} // existing databases/schemas/tables/etc (so we can apply "*")

	conn, err := pgConn("postgres")
	if err != nil {
		return nil, nil, err
	}

	// Load passwords. If we're using amazon RDS, this won't work and we just have to re-assert passwords every time :'(
	// maybe someday I'll figure out a way around this.
	passwords := map[string]string{}
	err = func() error {
		sql := `select s.usename, s.passwd from pg_shadow as s where s.passwd is not null;`
		rows, err := conn.Query(ctx, sql)
		if err != nil {
			return errors.WithStack(err)
		}
		for rows.Next() {
			var u, s string
			err := rows.Scan(&u, &s)
			if err != nil {
				return errors.WithStack(err)
			}
			passwords[u] = s
		}
		if err := rows.Err(); err != nil {
			return errors.WithStack(err)
		}
		return nil
	}()
	if err != nil {
		if strings.Contains(err.Error(), "permission denied for view pg_shadow") {
			// RDS suckage. Don't fret.
		} else {
			return nil, nil, err
		}
	}

	// Load every user (role). This list is the same no matter what database we connect to.

	sql := `select r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb,
                  r.rolcanlogin, r.rolreplication, r.rolconnlimit, r.rolvaliduntil,
                  r.rolconfig
           from pg_roles as r;`

	rows, err := conn.Query(ctx, sql)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var r pgRole
		err := rows.Scan(
			&r.RolName, &r.RolSuper, &r.RolInherit, &r.RolCreateRole, &r.RolCreateDB,
			&r.RolCanLogin, &r.RolReplication, &r.RolConnLimit, &r.RolValidUntil,
			&r.RolConfig,
		)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}
		if ignoreUsers[strings.ToLower(r.RolName)] {
			continue
		}
		if strings.HasPrefix(r.RolName, "pg_") {
			continue
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
		if r.RolCreateDB {
			grants[CreateDB.Name] = CreateDB
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
			Password: passwords[r.RolName],
			Grants:   grants,
			Valid:    true,
			Settings: settings,
			Roles:    map[string]bool{},
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, errors.WithStack(err)
	}

	// Load roles granted to each user

	sql = `select r.rolname, rr.rolname from pg_auth_members as a inner join pg_roles as r on r.oid = a.member inner join pg_roles as rr on rr.oid = a.roleid;`
	rows, err = conn.Query(ctx, sql)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	for rows.Next() {
		var (
			role   string
			parent string
		)
		if err := rows.Scan(&role, &parent); err != nil {
			return nil, nil, errors.WithStack(err)
		}
		if _, ok := out[role]; !ok {
			// ignored user
			continue
		}
		out[role].Roles[parent] = true
	}

	// Now go through each database, loading all the table permissions

	var dbnames []string
	sql = `select datname, datacl from pg_catalog.pg_database;`

	rows, err = conn.Query(ctx, sql)
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
		if ignoreDatabases[dbname] {
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

	ctx := context.Background()

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

	rows, err := conn.Query(ctx, sql)
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

	ctx := context.Background()

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

	rows, err := conn.Query(ctx, sql)
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

	ctx := context.Background()

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

	rows, err := conn.Query(ctx, sql)
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

	role, rlen, err := pgParseACLRoleString(input)
	if err != nil {
		return r, err
	}
	r.Role = role

	input = input[rlen:]

	if len(input) == 0 || input[0] != '=' {
		return r, errors.New("Expected equals sign after role name")
	}

	input = input[1:]
	skip := 0
chars:
	for _, ch := range input {
		if ch == '/' {
			break
		}
		for _, p := range permlist {
			for _, pp := range p {
				if pp.Pg == string(ch) {
					r.Perms = append(r.Perms, pp)
					skip++
					continue chars
				}
			}
		}
		return r, fmt.Errorf("Unhandled privilege character %#v", string(ch))
	}
	input = input[skip:]

	if len(input) == 0 {
		return r, errors.New("Expected forward slash")
	}
	if input[0] != '/' {
		return r, fmt.Errorf("Expected forward slash, got %#v", string(input[0]))
	}
	input = input[1:]

	granter, rlen, err := pgParseACLRoleString(input)
	if err != nil {
		return r, err
	}
	r.Granter = granter

	input = input[rlen:]

	if len(input) > 0 {
		return r, fmt.Errorf("Leftover text in ACL string: %#v", input)
	}
	return r, nil
}
func pgParseACLRoleString(str string) (string, int, error) {
	if len(str) == 0 {
		return "", 0, nil
	}

	max := 0
	raw := false
	quote := false
	esc := false

	var qstr strings.Builder

	for idx, ch := range str {
		max = idx

		if raw {
			if (ch >= 'a' && ch <= 'z') ||
				(ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') ||
				ch == '_' {
				continue
			}
			return str[:max], max, nil
		} else if quote {
			if esc {
				esc = false
				qstr.WriteRune(ch)
				continue
			} else {
				if ch == '\\' {
					esc = true
					continue
				} else if ch == '"' {
					return qstr.String(), max + 1, nil
				} else {
					qstr.WriteRune(ch)
				}
			}
		} else {
			if ch == '"' {
				quote = true
				continue
			} else if (ch >= 'a' && ch <= 'z') ||
				(ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') ||
				ch == '_' {
				raw = true
				continue
			} else {
				return "", 0, nil
			}
		}
	}

	if raw {
		return str, len(str), nil
	} else if quote {
		return "", 0, fmt.Errorf("Could not find closing quote from %#v", str)
	} else {
		return "", 0, fmt.Errorf("Could not parse role from %#v: Invalid state", str)
	}
}

func pgPasswordHash(user, p string) string {
	t := pgPasswordType(p)
	if t == 1 {
		// old mode
		//return pgPasswordMD5(user, p)
		// new mode
		return scramFromNew(p)
	}
	return p
}

func pgPasswordMD5(user, p string) string {
	return fmt.Sprintf("md5%x", md5.Sum([]byte(p+user)))
}

func pgPasswordEqual(user, p1, p2 string) bool {
	p1t := pgPasswordType(p1)
	p2t := pgPasswordType(p2)
	// if same type, string must equal
	if p1t == p2t {
		return p1 == p2
	}
	// we can compare plain text with the other two types.
	// swap so plain text is first if needed
	if p2t == 1 {
		p1, p1t, p2, p2t = p2, p2t, p1, p1t
	}
	// we can compare plain text to md5
	if p1t == 1 && p2t == 2 {
		return pgPasswordMD5(user, p1) == p2
	}
	// we can compare plain text to scram
	if p1t == 1 && p2t == 3 {
		hash, iterations, salt, ok := splitScram(p2)
		//fmt.Printf("hash %#v iterations %#v salt %#v storedkey %#v serverkey %#v ok %#v\n",
		//	hash, iterations, salt, storedkey, serverkey, ok)
		if !ok {
			return false
		}
		// hash p1 with p2's parameters so we can compare
		p := scramFromParameters(p1, hash, iterations, salt)
		return p == p2
	}
	return false
}

func splitScram(p string) (string, int, []byte, bool) {
	authPassword := strings.Split(p, "$")
	if len(authPassword) != 3 {
		return "", 0, nil, false
	}
	hash := authPassword[0]
	if hash != "SCRAM-SHA-256" {
		return "", 0, nil, false
	}
	authInfo := strings.Split(authPassword[1], ":")
	if len(authInfo) != 2 {
		return "", 0, nil, false
	}
	authValue := strings.Split(authPassword[2], ":")
	if len(authValue) != 2 {
		return "", 0, nil, false
	}
	iterations, err := strconv.ParseInt(authInfo[0], 10, 32)
	if err != nil {
		return "", 0, nil, false
	}
	salt, err := base64.StdEncoding.DecodeString(authInfo[1])
	if err != nil {
		return "", 0, nil, false
	}
	_, err = base64.StdEncoding.DecodeString(authValue[0])
	if err != nil {
		return "", 0, nil, false
	}
	_, err = base64.StdEncoding.DecodeString(authValue[1])
	if err != nil {
		return "", 0, nil, false
	}
	return hash, int(iterations), salt, true
}

func scramFromParameters(p1, hash string, iterations int, salt []byte) string {
	// Now we hash p1 with the right parameters to end up with the same SCRAM-SHA-256 string postgres will have in pg_shadow.

	// SCRAM-SHA-256:
	// SaltedPassword = PBKDF2(password, salt, iterations, SHA256)
	// ClientKey = HMAC-SHA256(SaltedPassword, "Client Key")
	// StoredKey = SHA256(ClientKey)
	// ServerKey = HMAC-SHA256(SaltedPassword, "Server Key")

	saltedPassword := pbkdf2.Key([]byte(p1), salt, iterations, sha256.Size, sha256.New)

	clientKeyHMAC := hmac.New(sha256.New, saltedPassword)
	clientKeyHMAC.Write([]byte("Client Key"))
	clientKey := clientKeyHMAC.Sum(nil)

	storedKeyHash := sha256.Sum256(clientKey)
	newStoredKey := storedKeyHash[:]

	serverKeyHMAC := hmac.New(sha256.New, saltedPassword)
	serverKeyHMAC.Write([]byte("Server Key"))
	newServerKey := serverKeyHMAC.Sum(nil)

	salt_b64 := base64.StdEncoding.EncodeToString(salt)
	storedkey_b64 := base64.StdEncoding.EncodeToString(newStoredKey)
	serverkey_b64 := base64.StdEncoding.EncodeToString(newServerKey)

	return fmt.Sprintf("%s$%d:%s$%s:%s",
		hash, iterations, salt_b64, storedkey_b64, serverkey_b64)
}

func scramFromNew(p string) string {
	hash := "SCRAM-SHA-256"
	iterations := 4096
	salt := make([]byte, 16)
	rand.Read(salt)

	saltedPassword := pbkdf2.Key([]byte(p), salt, iterations, sha256.Size, sha256.New)

	clientKeyHMAC := hmac.New(sha256.New, saltedPassword)
	clientKeyHMAC.Write([]byte("Client Key"))
	clientKey := clientKeyHMAC.Sum(nil)

	storedKeyHash := sha256.Sum256(clientKey)
	newStoredKey := storedKeyHash[:]

	serverKeyHMAC := hmac.New(sha256.New, saltedPassword)
	serverKeyHMAC.Write([]byte("Server Key"))
	newServerKey := serverKeyHMAC.Sum(nil)

	salt_b64 := base64.StdEncoding.EncodeToString(salt)
	storedkey_b64 := base64.StdEncoding.EncodeToString(newStoredKey)
	serverkey_b64 := base64.StdEncoding.EncodeToString(newServerKey)

	return fmt.Sprintf("%s$%d:%s$%s:%s",
		hash, iterations, salt_b64, storedkey_b64, serverkey_b64)
}

func pgPasswordType(p string) int {
	if p == "" {
		return 0 // special type for null / no password
	}
	if len(p) == 35 && strings.HasPrefix(p, "md5") {
		return 2
	}
	if strings.HasPrefix(p, "SCRAM-SHA-256") {
		return 3
	}
	return 1
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

func pgExecMain(ctx context.Context, sql string, args ...interface{}) error {
	return pgExec(ctx, "postgres", sql)
}
func pgExec(ctx context.Context, db string, sql string) error {
	defer timer(fmt.Sprintf("%#v %s", db, sql)).done()

	if db != lastPrintedDB && !quiet && !timing {
		fmt.Println("\\connect " + pgQuoteIdent(db))
		lastPrintedDB = db
	}

	if !timing && !quiet {
		fmt.Println(sql)
	}

	if dry {
		return nil
	}

	conn, err := pgConn(db)
	if err != nil {
		return err
	}

	_, err = conn.Exec(ctx, sql)
	return err
}
