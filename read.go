package main

import (
	"io/ioutil"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type Input struct {
	Users map[string]InputUser
}
type InputUser struct {
	Password  string
	Grants    InputGrants
	Databases map[string]InputDatabase
}
type InputDatabase struct {
	Grants  InputGrants
	Schemas map[string]InputSchema
}
type InputSchema struct {
	Grants    InputGrants
	Tables    map[string]InputTable
	Sequences map[string]InputSequence
}
type InputTable struct {
	Grants InputGrants
}
type InputSequence struct {
	Grants InputGrants
}
type InputGrants []string

func ReadFile(filepath string) (Input, error) {
	defer timer("parse " + filepath).done()

	var input Input

	buf, err := ioutil.ReadFile(filepath)
	if err != nil {
		return input, errors.Wrapf(err, "Read file %#v", filepath)
	}

	if err := yaml.Unmarshal(buf, &input); err != nil {
		return input, errors.Wrapf(err, "Parse file %#v", filepath)
	}

	return input, nil
}

// some really ugly data structure munging
func mergeInputs(inputs []Input) (map[string]User, error) {
	r := map[string]User{}

	for _, input := range inputs {
		for name, user := range input.Users {
			u := r[name]
			u.Name = name
			if u.Password == "" {
				u.Password = user.Password
			} else if user.Password != "" && user.Password != u.Password {
				return r, errors.Errorf("User %#v has two conflicting passwords defined", name)
			}

			if u.Grants == nil {
				u.Grants = map[string]Perm{}
			}
		outeruser:
			for _, ps := range user.Grants {
				s := permCanonical(ps)
				for _, p := range UserPerms {
					if permCanonical(p.Name) == s {
						u.Grants[p.Name] = p
						continue outeruser
					}
				}
				return r, errors.Errorf("Unhandled user permission %#v", ps)
			}

			if u.Databases == nil {
				u.Databases = map[string]Database{}
			}
			for dbname, db := range user.Databases {
				d := u.Databases[dbname]
				d.Name = dbname

				if d.Grants == nil {
					d.Grants = map[string]Perm{}
				}
			outerdb:
				for _, ps := range db.Grants {
					s := permCanonical(ps)
					for _, p := range DatabasePerms {
						if permCanonical(p.Name) == s {
							d.Grants[p.Name] = p
							continue outerdb
						}
					}
					return r, errors.Errorf("Unhandled database permission %#v", ps)
				}

				if d.Schemas == nil {
					d.Schemas = map[string]Schema{}
				}
				for schemaname, schema := range db.Schemas {
					s := d.Schemas[schemaname]
					s.Name = schemaname

					if s.Grants == nil {
						s.Grants = map[string]Perm{}
					}
				outerschema:
					for _, ps := range schema.Grants {
						str := permCanonical(ps)
						for _, p := range SchemaPerms {
							if permCanonical(p.Name) == str {
								s.Grants[p.Name] = p
								continue outerschema
							}
						}
						return r, errors.Errorf("Unhandled schema permission %#v", ps)
					}

					if s.Tables == nil {
						s.Tables = map[string]Table{}
					}
					for tablename, table := range schema.Tables {
						t := s.Tables[tablename]
						t.Name = tablename

						if t.Grants == nil {
							t.Grants = map[string]Perm{}
						}
					outertable:
						for _, ps := range table.Grants {
							s := permCanonical(ps)
							for _, p := range TablePerms {
								if permCanonical(p.Name) == s {
									t.Grants[p.Name] = p
									continue outertable
								}
							}
							return r, errors.Errorf("Unhandled table permission %#v", ps)
						}
						s.Tables[tablename] = t
					}

					if s.Sequences == nil {
						s.Sequences = map[string]Sequence{}
					}
					for sequencename, sequence := range schema.Sequences {
						seq := s.Sequences[sequencename]
						seq.Name = sequencename

						if seq.Grants == nil {
							seq.Grants = map[string]Perm{}
						}
					outersequence:
						for _, ps := range sequence.Grants {
							s := permCanonical(ps)
							for _, p := range SequencePerms {
								if permCanonical(p.Name) == s {
									seq.Grants[p.Name] = p
									continue outersequence
								}
							}
							return r, errors.Errorf("Unhandled sequence permission %#v", ps)
						}
						s.Sequences[sequencename] = seq
					}

					d.Schemas[schemaname] = s
				}
				u.Databases[dbname] = d
			}
			r[name] = u
		}
	}

	return r, nil
}
