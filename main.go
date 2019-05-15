package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx"
	"github.com/pkg/errors"
)

var (
	debug  = false
	timing = false
	dry    = false
	quiet  = false

	baseconfig = pgx.ConnConfig{
		User: "postgres",
	}
)

func main() {
	if err := mainRun(); err != nil {
		printErr(err)
		os.Exit(1)
	}
}

func mainRun() error {
	defer timer("total").done()

	var inpaths []string

	mode := "file"

	for _, arg := range os.Args[1:] {
		if arg == "-n" || arg == "-d" || arg == "--dry" {
			dry = true
			continue
		}
		if arg == "-q" || arg == "--quiet" {
			quiet = true
			continue
		}
		if arg == "--debug" {
			debug = true
			continue
		}
		if arg == "-t" || arg == "--timing" {
			timing = true
			continue
		}
		if arg == "-h" || arg == "--host" {
			mode = "host"
			continue
		}
		if arg == "-p" || arg == "--port" {
			mode = "port"
			continue
		}
		if arg == "-u" || arg == "--user" {
			mode = "user"
			continue
		}
		if arg == "--password" {
			mode = "password"
			continue
		}
		if arg == "--example" {
			example()
			os.Exit(1)
		}
		if strings.HasPrefix(arg, "-") {
			if arg != "--help" {
				fmt.Printf("Invalid argument %#v\n\n", arg)
			}
			usage()
			os.Exit(1)
		}

		switch mode {
		case "file":
			inpaths = append(inpaths, arg)
		case "host":
			baseconfig.Host = arg
		case "port":
			port, err := strconv.Atoi(arg)
			if err != nil {
				return err
			}
			if port < 1 || port > 65535 {
				fmt.Printf("Port number %d out of range\n", port)
				os.Exit(1)
			}
			baseconfig.Port = uint16(port)
		case "user":
			baseconfig.User = arg
		case "password":
			baseconfig.Password = arg
		default:
			return fmt.Errorf("Invalid argument mode %#v", mode)
		}

		mode = "file"
	}

	if mode != "file" {
		fmt.Printf("Missing %s argument\n\n", mode)
		usage()
		os.Exit(1)
	}

	var inputs []Input
	for _, inpath := range inpaths {
		input, err := ReadFile(inpath)
		if err != nil {
			return err
		}
		inputs = append(inputs, input)
	}

	newusers, err := mergeInputs(inputs)
	if err != nil {
		return err
	}

	oldusers, existing, err := pgSelectExisting()
	if err != nil {
		return err
	}

	// expand out grants for "*"
	for name, user := range newusers {
		for dbname, db := range user.Databases {
			for schemaname, schema := range db.Schemas {
				if schema.Tables != nil && existing[dbname].Schemas != nil {
					for tablename := range existing[dbname].Schemas[schemaname].Tables {
						t := schema.Tables[tablename]
						t.Name = tablename
						if t.Grants == nil {
							t.Grants = map[string]Perm{}
						}
						for _, p := range schema.Tables[pgDefaultMarker].Grants {
							t.Grants[p.Name] = p
						}
						schema.Tables[tablename] = t
					}
				}
				if schema.Sequences != nil && existing[dbname].Schemas != nil {
					for sequencename := range existing[dbname].Schemas[schemaname].Sequences {
						seq := schema.Sequences[sequencename]
						seq.Name = sequencename
						if seq.Grants == nil {
							seq.Grants = map[string]Perm{}
						}
						for _, p := range schema.Sequences[pgDefaultMarker].Grants {
							seq.Grants[p.Name] = p
						}
						schema.Sequences[sequencename] = seq
					}
				}
				db.Schemas[schemaname] = schema
			}
			user.Databases[dbname] = db
		}
		newusers[name] = user
	}

	var names []string
	for n := range newusers {
		names = append(names, n)
	}
	for n := range oldusers {
		_, ok := newusers[n]
		if !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		newuser := newusers[name]
		olduser := oldusers[name]

		if newuser.Name == "" {
			// skip users we haven't defined
			continue
		}

		if strings.ToLower(name) == "postgres" {
			return errors.Errorf("Managing role %#v isn't safe with a tool. Revoking superuser could be catastrophic for your database", name)
		}

		// A newly created user in postgres defaults to have some permissions,
		// such as inherit. Let's set them here, so when we create a new user it
		// correctly revokes these privileges without requiring another pass.
		if !olduser.Valid && newuser.Valid {
			if olduser.Grants == nil {
				olduser.Grants = map[string]Perm{}
			}
			olduser.Grants[Inherit.Name] = Inherit
		}

		if debug {
			fmt.Println("--", name, "--")
			fmt.Print("old: ")
			olduser.Print()
			fmt.Print("new: ")
			newuser.Print()
		}

		// "public" is a special built-in role for postgres. We ignore that one.
		if !olduser.Valid && newuser.Valid && name != "public" {
			if err := pgExecMain("CREATE ROLE " + pgQuoteIdent(name) + ";"); err != nil {
				return err
			}
		}

		// If the user is to be dropped, consider all permissions "revoked"
		if !newuser.Valid {
			newuser.Grants = nil
			newuser.Databases = nil
		}

		// revoke user attributes
		for _, p := range olduser.Grants {
			ok := false
			if newuser.Grants != nil {
				_, ok = newuser.Grants[p.Name]
			}
			if !ok {
				if err := pgExecMain("ALTER ROLE " + pgQuoteIdent(name) + " WITH NO" + p.Name + ";"); err != nil {
					return err
				}
			}
		}

		// grant user attributes
		for _, p := range newuser.Grants {
			ok := false
			if olduser.Grants != nil {
				_, ok = olduser.Grants[p.Name]
			}
			if !ok {
				if err := pgExecMain("ALTER ROLE " + pgQuoteIdent(name) + " WITH " + p.Name + ";"); err != nil {
					return err
				}
			}
		}

		// password changes
		h1 := pgPasswordHash(name, newuser.Password)
		h2 := pgPasswordHash(name, olduser.Password)

		// If the user will not have the login privilege, password changes will have no effect
		_, wantlogin := newuser.Grants[Login.Name]

		if h1 != h2 && wantlogin {
			if h1 == "" && h2 != "" {
				if err := pgExecMain("ALTER ROLE " + pgQuoteIdent(name) + " WITH PASSWORD NULL;"); err != nil {
					return err
				}
			} else {
				if err := pgExecMain("ALTER ROLE " + pgQuoteIdent(name) + " WITH PASSWORD " + pgQuote(h1) + ";"); err != nil {
					return err
				}
			}
		}

		// revoke
		for dbname, db := range olduser.Databases {
			// database
			for _, p := range db.Grants {
				ok := false
				if newuser.Databases != nil &&
					newuser.Databases[dbname].Grants != nil {
					_, ok = newuser.Databases[dbname].Grants[p.Name]
				}
				if !ok {
					if err := pgExecMain("REVOKE " + p.Name + " ON DATABASE " + pgQuoteIdent(dbname) + " FROM " + pgQuoteIdent(name) + ";"); err != nil {
						return err
					}
				}
			}
			for schemaname, schema := range db.Schemas {
				// schema
				for _, p := range schema.Grants {
					ok := false
					if newuser.Databases != nil &&
						newuser.Databases[dbname].Schemas != nil &&
						newuser.Databases[dbname].Schemas[schemaname].Grants != nil {
						_, ok = newuser.Databases[dbname].Schemas[schemaname].Grants[p.Name]
					}
					if !ok {
						if err := pgExec(dbname, "REVOKE "+p.Name+" ON SCHEMA "+pgQuoteIdent(schemaname)+" FROM "+pgQuoteIdent(name)+";"); err != nil {
							return err
						}
					}
				}
				for tablename, table := range schema.Tables {
					// table
					for _, p := range table.Grants {
						ok := false
						if newuser.Databases != nil &&
							newuser.Databases[dbname].Schemas != nil &&
							newuser.Databases[dbname].Schemas[schemaname].Tables != nil &&
							newuser.Databases[dbname].Schemas[schemaname].Tables[tablename].Grants != nil {
							_, ok = newuser.Databases[dbname].Schemas[schemaname].Tables[tablename].Grants[p.Name]
						}
						if !ok {
							sql := "REVOKE " + p.Name + " ON TABLE " + pgQuoteIdentPair(schemaname, tablename) + " FROM " + pgQuoteIdent(name) + ";"
							if tablename == pgDefaultMarker {
								sql = "ALTER DEFAULT PRIVILEGES FOR ROLE " + pgQuoteIdent(pgDefaultAssumeRole) + " IN SCHEMA " + pgQuoteIdent(schemaname) + " REVOKE " + p.Name + " ON TABLES FROM " + pgQuoteIdent(name) + ";"
							}
							if err := pgExec(dbname, sql); err != nil {
								return err
							}
						}
					}
				}
				for sequencename, sequence := range schema.Sequences {
					// sequence
					for _, p := range sequence.Grants {
						ok := false
						if newuser.Databases != nil &&
							newuser.Databases[dbname].Schemas != nil &&
							newuser.Databases[dbname].Schemas[schemaname].Sequences != nil &&
							newuser.Databases[dbname].Schemas[schemaname].Sequences[sequencename].Grants != nil {
							_, ok = newuser.Databases[dbname].Schemas[schemaname].Sequences[sequencename].Grants[p.Name]
						}
						if !ok {
							sql := "REVOKE " + p.Name + " ON SEQUENCE " + pgQuoteIdentPair(schemaname, sequencename) + " FROM " + pgQuoteIdent(name) + ";"
							if sequencename == pgDefaultMarker {
								sql = "ALTER DEFAULT PRIVILEGES FOR ROLE " + pgQuoteIdent(pgDefaultAssumeRole) + " IN SCHEMA " + pgQuoteIdent(schemaname) + " REVOKE " + p.Name + " ON SEQUENCES FROM " + pgQuoteIdent(name) + ";"
							}
							if err := pgExec(dbname, sql); err != nil {
								return err
							}
						}
					}
				}
			}
		}

		// grant
		for dbname, db := range newuser.Databases {
			// database
			for _, p := range db.Grants {
				ok := false
				if olduser.Databases != nil &&
					olduser.Databases[dbname].Grants != nil {
					_, ok = olduser.Databases[dbname].Grants[p.Name]
				}
				if !ok {
					if err := pgExecMain("GRANT " + p.Name + " ON DATABASE " + pgQuoteIdent(dbname) + " TO " + pgQuoteIdent(name) + ";"); err != nil {
						return err
					}
				}
			}
			for schemaname, schema := range db.Schemas {
				// schema
				for _, p := range schema.Grants {
					ok := false
					if olduser.Databases != nil &&
						olduser.Databases[dbname].Schemas != nil &&
						olduser.Databases[dbname].Schemas[schemaname].Grants != nil {
						_, ok = olduser.Databases[dbname].Schemas[schemaname].Grants[p.Name]
					}
					if !ok {
						if err := pgExec(dbname, "GRANT "+p.Name+" ON SCHEMA "+pgQuoteIdent(schemaname)+" TO "+pgQuoteIdent(name)+";"); err != nil {
							return err
						}
					}
				}
				for tablename, table := range schema.Tables {
					// table
					for _, p := range table.Grants {
						ok := false
						if olduser.Databases != nil &&
							olduser.Databases[dbname].Schemas != nil &&
							olduser.Databases[dbname].Schemas[schemaname].Tables != nil &&
							olduser.Databases[dbname].Schemas[schemaname].Tables[tablename].Grants != nil {
							_, ok = olduser.Databases[dbname].Schemas[schemaname].Tables[tablename].Grants[p.Name]
						}
						if !ok {
							sql := "GRANT " + p.Name + " ON TABLE " + pgQuoteIdentPair(schemaname, tablename) + " TO " + pgQuoteIdent(name) + ";"
							if tablename == pgDefaultMarker {
								sql = "ALTER DEFAULT PRIVILEGES FOR ROLE " + pgQuoteIdent(pgDefaultAssumeRole) + " IN SCHEMA " + pgQuoteIdent(schemaname) + " GRANT " + p.Name + " ON TABLES TO " + pgQuoteIdent(name) + ";"
							}
							if err := pgExec(dbname, sql); err != nil {
								return err
							}
						}
					}
				}
				for sequencename, sequence := range schema.Sequences {
					// sequence
					for _, p := range sequence.Grants {
						ok := false
						if olduser.Databases != nil &&
							olduser.Databases[dbname].Schemas != nil &&
							olduser.Databases[dbname].Schemas[schemaname].Sequences != nil &&
							olduser.Databases[dbname].Schemas[schemaname].Sequences[sequencename].Grants != nil {
							_, ok = olduser.Databases[dbname].Schemas[schemaname].Sequences[sequencename].Grants[p.Name]
						}
						if !ok {
							sql := "GRANT " + p.Name + " ON SEQUENCE " + pgQuoteIdentPair(schemaname, sequencename) + " TO " + pgQuoteIdent(name) + ";"
							if sequencename == pgDefaultMarker {
								sql = "ALTER DEFAULT PRIVILEGES FOR ROLE " + pgQuoteIdent(pgDefaultAssumeRole) + " IN SCHEMA " + pgQuoteIdent(schemaname) + " GRANT " + p.Name + " ON SEQUENCES TO " + pgQuoteIdent(name) + ";"
							}
							if err := pgExec(dbname, sql); err != nil {
								return err
							}
						}
					}
				}
			}
		}

		// drop users
		// "public" is a special built-in role for postgres. We ignore that one.
		if olduser.Valid && !newuser.Valid && name != "public" {
			if err := pgExecMain("DROP ROLE " + pgQuoteIdent(name) + ";"); err != nil {
				return err
			}
		}
	}

	return nil
}
