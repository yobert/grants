package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
)

var (
	debug  = false
	timing = false
	dry    = false
	quiet  = false

	baseconfig *pgx.ConnConfig

	envfiles []string
)

func main() {

	if err := mainRun(); err != nil {
		printErr(err)
		os.Exit(1)
	}
}

func mainRun() error {
	defer timer("total").done()

	ctx := context.Background()

	var inpaths []string

	mode := "file"

	for _, arg := range os.Args[1:] {
		if mode != "file" && strings.HasPrefix(arg, "-") {
			fmt.Printf("Error: --%s argument expects a value\n\n", mode)
			usage()
			os.Exit(1)
		}

		if arg == "--env-file" {
			mode = "env-file"
			continue
		}
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
		case "env-file":
			envfiles = append(envfiles, arg)
		default:
			return fmt.Errorf("Invalid argument mode %#v", mode)
		}

		mode = "file"
	}

	if mode != "file" {
		fmt.Printf("Error: --%s argument expects a value\n\n", mode)
		usage()
		os.Exit(1)
	}

	if len(inpaths) == 0 {
		inpaths = append(inpaths, "grants.yaml")
	}

	if len(envfiles) == 0 {
		if _, err := os.Stat(".env"); err == nil {
			envfiles = append(envfiles, ".env")
		}
	}

	if len(envfiles) > 0 {
		if err := godotenv.Load(envfiles...); err != nil {
			return err
		}
	}

	config, err := parseConfig()
	if err != nil {
		return err
	}
	baseconfig = config

	var inputs []Input
	for _, inpath := range inpaths {
		input, err := ReadFile(inpath)
		if err != nil {
			return err
		}
		inputs = append(inputs, input)
	}

	newusers, defaultPrivRole, err := mergeInputs(inputs)
	if err != nil {
		return err
	}

	if defaultPrivRole == "" {
		defaultPrivRole = "postgres"
	}

	oldusers, existing, err := pgSelectExisting(defaultPrivRole)
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
			for _, perm := range DefaultNewUserPerms {
				olduser.Grants[perm.Name] = perm
			}
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
			if err := pgExecMain(ctx, "CREATE ROLE "+pgQuoteIdent(name)+";"); err != nil {
				return err
			}
		}

		// If the user is to be dropped, consider all permissions "revoked" and all settings default
		if !newuser.Valid {
			newuser.Grants = nil
			newuser.Databases = nil
			newuser.Settings = nil
			newuser.Roles = nil
		}

		// revoke user attributes
		if newuser.Valid {
			for _, p := range olduser.Grants {
				ok := false
				if newuser.Grants != nil {
					_, ok = newuser.Grants[p.Name]
				}
				if !ok {
					if err := pgExecMain(ctx, "ALTER ROLE "+pgQuoteIdent(name)+" WITH NO"+p.Name+";"); err != nil {
						return err
					}
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
				if err := pgExecMain(ctx, "ALTER ROLE "+pgQuoteIdent(name)+" WITH "+p.Name+";"); err != nil {
					return err
				}
			}
		}

		// settings additions or changes
		for k, v := range newuser.Settings {
			if olduser.Settings == nil || olduser.Settings[k] != v {
				if err := pgExecMain(ctx, "ALTER ROLE "+pgQuoteIdent(name)+" SET "+pgQuoteIdent(k)+" = "+pgQuote(v)+";"); err != nil {
					return err
				}
			}
		}
		// settings removals
		if newuser.Valid {
			for k := range olduser.Settings {
				if newuser.Settings == nil || newuser.Settings[k] == "" {
					if err := pgExecMain(ctx, "ALTER ROLE "+pgQuoteIdent(name)+" SET "+pgQuoteIdent(k)+" = DEFAULT;"); err != nil {
						return err
					}
				}
			}
		}

		// role additions
		for role := range newuser.Roles {
			if olduser.Roles == nil || !olduser.Roles[role] {
				if err := pgExecMain(ctx, "GRANT "+pgQuoteIdent(role)+" TO "+pgQuoteIdent(name)+";"); err != nil {
					return err
				}
			}
		}
		// role removals
		if newuser.Valid {
			for role := range olduser.Roles {
				if newuser.Roles == nil || !newuser.Roles[role] {
					if err := pgExecMain(ctx, "REVOKE "+pgQuoteIdent(role)+" FROM "+pgQuoteIdent(name)+";"); err != nil {
						return err
					}
				}
			}
		}

		// If the user will not have the login privilege, password changes will have no effect
		_, wantlogin := newuser.Grants[Login.Name]

		// password changes
		if wantlogin && !pgPasswordEqual(name, olduser.Password, newuser.Password) {
			if newuser.Password == "" && olduser.Password != "" {
				if err := pgExecMain(ctx, "ALTER ROLE "+pgQuoteIdent(name)+" WITH PASSWORD NULL;"); err != nil {
					return err
				}
			} else {
				if err := pgExecMain(ctx, "ALTER ROLE "+pgQuoteIdent(name)+" WITH PASSWORD "+pgQuote(pgPasswordHash(name, newuser.Password))+";"); err != nil {
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
					if err := pgExecMain(ctx, "REVOKE "+p.Name+" ON DATABASE "+pgQuoteIdent(dbname)+" FROM "+pgQuoteIdent(name)+";"); err != nil {
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
						if err := pgExec(ctx, dbname, "REVOKE "+p.Name+" ON SCHEMA "+pgQuoteIdent(schemaname)+" FROM "+pgQuoteIdent(name)+";"); err != nil {
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
								sql = "ALTER DEFAULT PRIVILEGES FOR ROLE " + pgQuoteIdent(defaultPrivRole) + " IN SCHEMA " + pgQuoteIdent(schemaname) + " REVOKE " + p.Name + " ON TABLES FROM " + pgQuoteIdent(name) + ";"
							}
							if err := pgExec(ctx, dbname, sql); err != nil {
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
								sql = "ALTER DEFAULT PRIVILEGES FOR ROLE " + pgQuoteIdent(defaultPrivRole) + " IN SCHEMA " + pgQuoteIdent(schemaname) + " REVOKE " + p.Name + " ON SEQUENCES FROM " + pgQuoteIdent(name) + ";"
							}
							if err := pgExec(ctx, dbname, sql); err != nil {
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
					if err := pgExecMain(ctx, "GRANT "+p.Name+" ON DATABASE "+pgQuoteIdent(dbname)+" TO "+pgQuoteIdent(name)+";"); err != nil {
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
						if err := pgExec(ctx, dbname, "GRANT "+p.Name+" ON SCHEMA "+pgQuoteIdent(schemaname)+" TO "+pgQuoteIdent(name)+";"); err != nil {
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
								sql = "ALTER DEFAULT PRIVILEGES FOR ROLE " + pgQuoteIdent(defaultPrivRole) + " IN SCHEMA " + pgQuoteIdent(schemaname) + " GRANT " + p.Name + " ON TABLES TO " + pgQuoteIdent(name) + ";"
							}
							if err := pgExec(ctx, dbname, sql); err != nil {
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
								sql = "ALTER DEFAULT PRIVILEGES FOR ROLE " + pgQuoteIdent(defaultPrivRole) + " IN SCHEMA " + pgQuoteIdent(schemaname) + " GRANT " + p.Name + " ON SEQUENCES TO " + pgQuoteIdent(name) + ";"
							}
							if err := pgExec(ctx, dbname, sql); err != nil {
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
			if err := pgExecMain(ctx, "DROP ROLE "+pgQuoteIdent(name)+";"); err != nil {
				return err
			}
		}
	}

	return nil
}

// This is a little goofy. That's because I want it to assume the right thing in the typical case of
// your grants.yaml being defined next to your application, and so a .env file will define how the application
// talks to the database-- as opposed to how the grants tool should talk to the database, which will need
// elevated permissions.
//
// Most applications will just define DATABASE_URL. This tool will assume user "postgres" with no password and
// the same host setting as DATABASE_URL. These assumptions can be overridden by:
// GRANTS_PGUSER
// GRANTS_PGPASSWORD
// GRANTS_PGHOST
// GRANTS_PGPORT
func parseConfig() (*pgx.ConnConfig, error) {
	appconfig, err := pgx.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		return nil, fmt.Errorf("Error parsing DATABASE_URL: %w", err)
	}

	config, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}

	config.Host = appconfig.Host
	config.Port = appconfig.Port

	config.Database = "postgres"
	config.User = "postgres"

	if v := os.Getenv("GRANTS_PGUSER"); v != "" {
		config.User = v
	}
	if v := os.Getenv("GRANTS_PGPASSWORD"); v != "" {
		config.Password = v
	}
	if v := os.Getenv("GRANTS_HOST"); v != "" {
		config.Host = v
	}
	if v := os.Getenv("GRANTS_PGPORT"); v != "" {
		i, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("Error parsing port number from GRANTS_PGPORT: %w", err)
		}
		config.Port = uint16(i)
	}

	return config, nil
}
