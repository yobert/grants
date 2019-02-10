package main

import (
	"io/ioutil"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type Input struct {
	Users map[string]InputUser
}

type InputUser struct {
	Password string
	Grants   map[string]map[string][]string
	Flags    []string
}

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
				u.Grants = map[string]map[string]map[string]Perm{}
			}
			if u.Perms == nil {
				u.Perms = map[string]Perm{}
			}
			for db, tables := range user.Grants {
				if u.Grants[db] == nil {
					u.Grants[db] = map[string]map[string]Perm{}
				}
				for table, grants := range tables {
					if u.Grants[db][table] == nil {
						u.Grants[db][table] = map[string]Perm{}
					}
				grantloop:
					for _, gs := range grants {
						s := strings.TrimSpace(gs)
						s = strings.ToUpper(s)
						for _, p := range Perms {
							if strings.ToUpper(p.Name) == s {
								u.Grants[db][table][p.Name] = p
								continue grantloop
							}
						}
						return r, errors.Errorf("Unhandled grant type %#v", gs)
					}
				}
			}
		permloop:
			for _, ps := range user.Flags {
				s := strings.TrimSpace(ps)
				s = strings.ToUpper(s)
				for _, p := range UserPerms {
					if strings.ToUpper(p.Name) == s {
						u.Perms[p.Name] = p
						continue permloop
					}
				}
				return r, errors.Errorf("Unhandled user permission %#v", ps)
			}

			// Don't force you to declare LOGIN for everybody
			if u.Password != "" {
				u.Perms[Login.Name] = Login
			}

			r[name] = u
		}
	}

	return r, nil
}
