package main

import (
	"fmt"
	"os"
)

func main() {
	if err := main_run(); err != nil {
		printErr(err)
		os.Exit(1)
	}
}

func main_run() error {
	var inputs []Input

	for _, inpath := range os.Args[1:] {
		input, err := ReadFile(inpath)
		if err != nil {
			return err
		}
		inputs = append(inputs, input)
	}

	existing, err := pgSelectExisting()
	if err != nil {
		return err
	}

	for _, user := range existing {
		fmt.Println(user)
		for dbname, tables := range user.Grants {
			fmt.Println("\t" + dbname)
			for tablename, grants := range tables {
				fmt.Println("\t\t" + tablename)
				fmt.Println("\t\t\t" + grants.String())
			}
		}
	}

	return nil
}
