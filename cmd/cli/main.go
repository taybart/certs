package main

import (
	"flags"

	"github.com/journeyai/certool"
)

func init() {
	flags.Parse()
}

func main() {
	ct := certool.NewCertool()
	ct.NewKey()
}
