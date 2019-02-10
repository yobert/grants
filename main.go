package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

const debug = false

var dry = false

func main() {
	if err := main_run(); err != nil {
		printErr(err)
		os.Exit(1)
	}
}

func main_run() error {
	var inputs []Input

	for _, inpath := range os.Args[1:] {
		if inpath == "-n" || inpath == "--dry" {
			dry = true
			continue
		}
		if strings.HasPrefix(inpath, "-") {
			fmt.Println(`Usage:

  grants [options] <files...>

Options:

  -h, --help:  Display this help
  -n, --dry:   Dry run (display SQL only)

Input file syntax:

users:
  myuser:
    password: supersecret
    grants:
      mydatabase:
        mytable:
          - SELECT
          - INSERT
          - UPDATE

  mysuperuser:
    password: evenmoresecret
    flags:
      - superuser

  # user with blank or missing password will be dropped.
  usertobedropped:
    password:
`)
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
			if err := pgExecMain("CREATE ROLE " + name + ";"); err != nil {
				return err
			}
		}

		// If the user is to be dropped, consider all permissions "revoked"
		if newuser.Password == "" {
			newuser.Grants = nil
			newuser.Perms = nil
		}

		// password changes
		if h1 != h2 {
			if h1 == "" && h2 != "" {
				if err := pgExecMain("ALTER USER " + name + " WITH PASSWORD NULL;"); err != nil {
					return err
				}
			} else {
				if err := pgExecMain("ALTER USER " + name + " WITH PASSWORD " + pgQuote(h1) + ";"); err != nil {
					return err
				}
			}
		}

		// revoke user attributes
		for _, p := range olduser.Perms {
			ok := false
			if newuser.Perms != nil {
				_, ok = newuser.Perms[p.Name]
			}
			if !ok {
				if err := pgExecMain("ALTER USER " + name + " WITH NO" + p.Name + ";"); err != nil {
					return err
				}
			}
		}

		// grant user attributes
		for _, p := range newuser.Perms {
			ok := false
			if olduser.Perms != nil {
				_, ok = olduser.Perms[p.Name]
			}
			if !ok {
				if err := pgExecMain("ALTER USER " + name + " WITH " + p.Name + ";"); err != nil {
					return err
				}
			}
		}

		// revoke table permissions
		for dbname, tables := range olduser.Grants {
			for tablename, grants := range tables {
				for _, p := range grants {
					ok := false
					if newuser.Grants != nil && newuser.Grants[dbname] != nil && newuser.Grants[dbname][tablename] != nil {
						_, ok = newuser.Grants[dbname][tablename][p.Name]
					}
					if !ok {
						if err := pgExec(dbname, "REVOKE "+p.Name+" ON TABLE "+tablename+" FROM "+name+";"); err != nil {
							return err
						}
					}
				}
			}
		}

		// grant table permissions
		for dbname, tables := range newuser.Grants {
			for tablename, grants := range tables {
				for _, p := range grants {
					ok := false
					if olduser.Grants != nil && olduser.Grants[dbname] != nil && olduser.Grants[dbname][tablename] != nil {
						_, ok = olduser.Grants[dbname][tablename][p.Name]
					}
					if !ok {
						if err := pgExec(dbname, "GRANT "+p.Name+" ON TABLE "+tablename+" TO "+name+";"); err != nil {
							return err
						}
					}
				}
			}
		}

		// drop users
		if olduser.Name != "" && newuser.Password == "" {
			if err := pgExecMain("DROP ROLE " + name + ";"); err != nil {
				return err
			}
		}
	}

	return nil
}
