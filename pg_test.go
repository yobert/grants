package main

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestParseACL(t *testing.T) {
	type acltest struct {
		input string
		acl   pgACL
	}
	tests := []acltest{
		{"hey=ra/boss", pgACL{Role: "hey", Granter: "boss", Perms: []Perm{Select, Insert}}},
		{"\"_\\\"messy.=/name\"=ra/\"messy=/.boss\"", pgACL{Role: "_\"messy.=/name", Granter: "messy=/.boss", Perms: []Perm{Select, Insert}}},
	}

	for testi, test := range tests {
		t.Run(fmt.Sprintf("case_%d", testi), func(t *testing.T) {
			acl, err := pgParseACL(test.input, DatabasePerms, SchemaPerms, TablePerms, SequencePerms)
			if err != nil {
				t.Errorf("Test %#v: %v", test.input, err)
				return
			}
			if acl.Role != test.acl.Role || acl.Granter != test.acl.Granter {
				t.Errorf("Test %#v expected role %#v granter %#v: got role %#v granter %#v",
					test.input,
					test.acl.Role, test.acl.Granter, acl.Role, acl.Granter)
				return
			}
			var got []string
			for _, p := range acl.Perms {
				got = append(got, p.Name)
			}
			var want []string
			for _, p := range test.acl.Perms {
				want = append(want, p.Name)
			}
			sort.Strings(got)
			sort.Strings(want)
			gots := strings.Join(got, ", ")
			wants := strings.Join(want, ", ")
			if gots != wants {
				t.Errorf("Test %#v expected permissions %s: got %s", test.input, wants, gots)
			}
		})
	}
}

func TestParseACLRoleString(t *testing.T) {
	type rtest struct {
		input    string
		role     string
		leftover string
		err      string
	}
	tests := []rtest{
		{"", "", "", ""},
		{"hey", "hey", "", ""},
		{"hey ", "hey", " ", ""},
		{"\"hey \"", "hey ", "", ""},
		{"\"hey \" ", "hey ", " ", ""},
		{"\"hey ", "hey ", " ", "Could not find closing quote"},
	}

	for testi, test := range tests {
		t.Run(fmt.Sprintf("case_%d", testi), func(t *testing.T) {
			role, l, err := pgParseACLRoleString(test.input)
			if err != nil {
				if test.err != "" {
					if strings.Contains(err.Error(), test.err) {
						return // cool
					}
					t.Errorf("Test %#v: Expected error %#v, got %v", test.input, test.err, err)
					return
				}
				t.Errorf("Test %#v: %v", test.input, err)
				return
			}
			if test.err != "" {
				t.Errorf("Test %#v: Expected error %#v, got no error", test.input, test.err)
				return
			}
			leftover := test.input[l:]
			if role != test.role || leftover != test.leftover {
				t.Errorf("Test %#v: Expected role %#v leftover %#v, got role %#v leftover %#v",
					test.input,
					test.role, test.leftover,
					role, leftover)
				return
			}
		})
	}
}
