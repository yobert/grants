package main

import "fmt"

func example() {
	fmt.Print(`users:
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
              # Separate multiple tables and sequences with spaces
              sometable someothertable:
                grants:
                  - SELECT
                  - INSERT
                  - UDPATE
            sequences:
              sometable_id_seq:
                grants:
                  - USAGE

  anotheruser:
    password: md55dcfe5d57dbd396467cf7a9d417ac29d # Passwords may be already hashed. This one is "hi"
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
