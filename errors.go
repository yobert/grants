package main

import (
	"fmt"

	"github.com/pkg/errors"
)

type stackTracer interface {
	StackTrace() errors.StackTrace
}

func printErr(e error) {
	fmt.Println(e)

	err, ok := errors.Cause(e).(stackTracer)
	if !ok {
		return
	}

	st := err.StackTrace()
	for i, v := range st {
		fmt.Println(i, v)
	}
}
