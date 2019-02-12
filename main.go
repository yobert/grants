package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/pkg/errors"
)

var (
	debug = false
	dry   = false
)

func main() {
	if err := mainRun(); err != nil {
		printErr(err)
		os.Exit(1)
	}
}

func mainRun() error {
	var inputs []Input

	for _, inpath := range os.Args[1:] {
		if inpath == "-n" || inpath == "--dry" {
			dry = true
			continue
		}
		if inpath == "-d" || inpath == "--debug" {
			debug = true
			continue
		}
		if strings.HasPrefix(inpath, "-") {
			fmt.Println(`Usage:

  grants [options] <files...>

Options:

  -h, --help:  Display this help
  -n, --dry:   Dry run (display SQL only)
  -d, --debug: Also print debug output

Input file syntax:

users:
  myuser:
    password: supersecret
    grants:
      - LOGIN
    databases:
      mydatabase:
        grants:
          - CONNECT
        schemas:
          public:
            grants:
              - USAGE
            tables:
              sometable:
                grants:
                  - SELECT
                  - INSERT
                  - UDPATE
            sequences:
              sometable_id_seq:
                grants:
                  - USAGE

  mysuperuser:
    password: evenmoresecret
    grants:
      - SUPERUSER

  # user with blank or missing password will be dropped.
  usertobedropped:
    password:`)
			os.Exit(1)
		}

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

	oldusers, err := pgSelectExisting()
	if err != nil {
		return err
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

		if debug {
			fmt.Println("--", name, "--")
			fmt.Print("old: ")
			olduser.Print()
			fmt.Print("new: ")
			newuser.Print()
		}

		h1 := pgPasswordHash(name, newuser.Password)
		h2 := pgPasswordHash(name, olduser.Password)

		if olduser.Name == "" && newuser.Password != "" {
			if err := pgExecMain("CREATE ROLE " + pgQuoteIdent(name) + ";"); err != nil {
				return err
			}
		}

		// If the user is to be dropped, consider all permissions "revoked"
		if newuser.Password == "" {
			newuser.Grants = nil
			newuser.Databases = nil
		}

		// password changes
		if h1 != h2 {
			if h1 == "" && h2 != "" {
				if err := pgExecMain("ALTER USER " + pgQuoteIdent(name) + " WITH PASSWORD NULL;"); err != nil {
					return err
				}
			} else {
				if err := pgExecMain("ALTER USER " + pgQuoteIdent(name) + " WITH PASSWORD " + pgQuote(h1) + ";"); err != nil {
					return err
				}
			}
		}

		// revoke user attributes
		for _, p := range olduser.Grants {
			ok := false
			if newuser.Grants != nil {
				_, ok = newuser.Grants[p.Name]
			}
			if !ok {
				if err := pgExecMain("ALTER USER " + pgQuoteIdent(name) + " WITH NO" + p.Name + ";"); err != nil {
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
				if err := pgExecMain("ALTER USER " + pgQuoteIdent(name) + " WITH " + p.Name + ";"); err != nil {
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
		if olduser.Name != "" && newuser.Password == "" {
			if err := pgExecMain("DROP ROLE " + pgQuoteIdent(name) + ";"); err != nil {
				return err
			}
		}
	}

	return nil
}
