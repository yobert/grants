Grants
------

This is a tool for declaring database permissions for PostgreSQL (and soon MySQL).
The idea is you specify a user and password, and which database tables it has which
permissions to select or modify.

An example input file:

```yaml
users:
  myuser:
    password: $PASSWORD_FROM_ENVIRONMENT_VARIABLE
    grants:
      - LOGIN
    databases:
      $DATABASE_NAME_FROM_ENVIRONMENT_VARIABLE:
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
              othertable anothertable athirdtable:
                grants:
                  - SELECT
                  - INSERT
                  - UPDATE
                  - DELETE
            sequences:
              othertable_id_seq:
                grants:
                  - USAGE
              anothertable athirdtable:
                grants:
                  - USAGE
```

Installation
------------

    go install github.com/yobert/grants

Usage
-----

    grants [path/to/yaml/file]

More information in --help and --example. Please file issues if you find bugs! Thanks!
