package main

import "fmt"

func usage() {
	fmt.Print(`Usage:

  grants [options] <input yaml files...>

Options:

  --help:        Display this help and exit
  --example:     Print example input file and exit

  -n, -d, --dry: Dry run (no changes will be executed)
  -q, --quiet:   Quiet (don't print SQL)
  -t, --timing:  Print timings
  --debug:       Print debug output

  -h, --host:    Host to connect to, or unix socket path
  -p, --port:    Port (default 5432)
  -u, --user:    User (default "postgres")
  --password:    Password on the command line. Insecure!

  --env-file:    Load environment variables from file. Repeatable
`)
}

func example() {
	fmt.Print(`users:
  myuser:
    password: supersecret
    grants:
      - LOGIN
    settings:
      statement_timeout: 60s
      lock_timeout: 30s
    databases:
      mydatabase:
        grants:
          - CONNECT
        schemas:
          public:
            grants:
              - USAGE
            tables:
              # Separate multiple tables and sequences with spaces
              sometable someothertable:
                grants:
                  - SELECT
                  - INSERT
                  - UPDATE
            sequences:
              sometable_id_seq:
                grants:
                  - USAGE

  anotheruser:
    password: md5ab1e0c4dd8740af7769758482c72d12a # Passwords may be already hashed. This one is "hi"
    grants:
      - login # Grants may be lowercase
    databases:
      mydatabase:
        grants:
          - connect
        schemas:
          public:
            grants:
              - usage
            # Wildcards allowed for tables and sequences
            tables:
              '*':
                grants:
                  - select
            sequences:
              '*':
                grants:
                  - usage

  mysuperuser:
    password: evenmoresecret
    grants:
      - SUPERUSER

  # user with no grants will be dropped.
  usertobedropped:
    password: somepassword
`)
}
