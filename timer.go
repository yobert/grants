package main

import (
	"fmt"
	"time"
)

type timerType struct {
	title string
	time  time.Time
}

func (t timerType) done() {
	if timing {
		dur := time.Since(t.time)
		fmt.Printf("%12s │ %s\n", formatDur(dur), t.title)
	}
}

func timer(title string) timerType {
	return timerType{
		time:  time.Now(),
		title: title,
	}
}

func formatDur(d time.Duration) string {
	if d > time.Second*10 {
		d = d.Truncate(time.Second)
	} else if d > time.Millisecond*10 {
		d = d.Truncate(time.Millisecond)
	} else if d > time.Microsecond*10 {
		d = d.Truncate(time.Microsecond)
	}
	return d.String()
}
