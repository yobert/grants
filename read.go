package main

import (
	"io/ioutil"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type Input struct {
	Users           map[string]InputUser
	DefaultPrivRole string `yaml:"default_priv_role"`
}
type InputUser struct {
	Password  string
	Grants    InputGrants
	Databases map[string]InputDatabase
	Settings  map[string]string
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
func mergeInputs(inputs []Input) (map[string]User, string, error) {
	r := map[string]User{}
	dr := ""

	for _, input := range inputs {
		if input.DefaultPrivRole != "" {
			if dr != "" && dr != input.DefaultPrivRole {
				return r, dr, errors.Errorf("Conflicting definitions of default_priv_role: %#v and %#v", dr, input.DefaultPrivRole)
			}
			dr = input.DefaultPrivRole
		}

		for name, user := range input.Users {
			for _, name := range split(name) {
				u := r[name]
				u.Name = name
				u.Settings = map[string]string{}
				for k, v := range user.Settings {
					u.Settings[strings.ToLower(k)] = v
				}
				if u.Password == "" {
					u.Password = user.Password
				} else if user.Password != "" && user.Password != u.Password {
					return r, dr, errors.Errorf("User %#v has two conflicting passwords defined", name)
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
							u.Valid = true
							continue outeruser
						}
					}
					return r, dr, errors.Errorf("Unhandled user permission %#v", ps)
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
								u.Valid = true
								continue outerdb
							}
						}
						return r, dr, errors.Errorf("Unhandled database permission %#v", ps)
					}

					if d.Schemas == nil {
						d.Schemas = map[string]Schema{}
					}
					for schemaname, schema := range db.Schemas {
						for _, schemaname := range split(schemaname) {
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
										u.Valid = true
										continue outerschema
									}
								}
								return r, dr, errors.Errorf("Unhandled schema permission %#v", ps)
							}

							if s.Tables == nil {
								s.Tables = map[string]Table{}
							}
							for tablename, table := range schema.Tables {
								for _, tablename := range split(tablename) {

									t := s.Tables[tablename]
									t.Name = tablename

									if t.Grants == nil {
										t.Grants = map[string]Perm{}
									}
								outertable:
									for _, ps := range table.Grants {
										s := permCanonical(ps)
										if s == "*" {
											for _, p := range TablePerms {
												t.Grants[p.Name] = p
												u.Valid = true
											}
										} else {
											for _, p := range TablePerms {
												if permCanonical(p.Name) == s {
													t.Grants[p.Name] = p
													u.Valid = true
													continue outertable
												}
											}
											return r, dr, errors.Errorf("Unhandled table permission %#v", ps)
										}
									}
									s.Tables[tablename] = t
								}
							}

							if s.Sequences == nil {
								s.Sequences = map[string]Sequence{}
							}
							for sequencename, sequence := range schema.Sequences {
								for _, sequencename := range split(sequencename) {
									seq := s.Sequences[sequencename]
									seq.Name = sequencename

									if seq.Grants == nil {
										seq.Grants = map[string]Perm{}
									}
								outersequence:
									for _, ps := range sequence.Grants {
										s := permCanonical(ps)
										if s == "*" {
											for _, p := range SequencePerms {
												seq.Grants[p.Name] = p
												u.Valid = true
											}
										} else {
											for _, p := range SequencePerms {
												if permCanonical(p.Name) == s {
													seq.Grants[p.Name] = p
													u.Valid = true
													continue outersequence
												}
											}
											return r, dr, errors.Errorf("Unhandled sequence permission %#v", ps)
										}
									}
									s.Sequences[sequencename] = seq
								}
							}

							d.Schemas[schemaname] = s
						}
					}
					u.Databases[dbname] = d
				}
				r[name] = u
			}
		}
	}

	return r, dr, nil
}

func split(in string) []string {
	var out []string
	for _, v := range strings.Split(in, " ") {
		v = strings.TrimSpace(v)
		out = append(out, v)
	}
	return out
}
