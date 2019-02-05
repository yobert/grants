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
	Password string
	Grants   map[string]map[string][]string
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
