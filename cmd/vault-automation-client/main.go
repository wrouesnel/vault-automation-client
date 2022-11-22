package main

import (
	"os"

	"github.com/wrouesnel/vault-automation-client/pkg/entrypoint"
	"github.com/wrouesnel/vault-automation-client/pkg/envutil"

	"github.com/samber/lo"
)

func main() {
	env := lo.Must(envutil.FromEnvironment(os.Environ()))

	args := entrypoint.LaunchArgs{
		StdIn:  os.Stdin,
		StdOut: os.Stdout,
		StdErr: os.Stderr,
		Env:    env,
		Args:   os.Args[1:],
	}
	ret := entrypoint.Entrypoint(args)
	os.Exit(ret)
}
