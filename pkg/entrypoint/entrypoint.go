package entrypoint

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/samber/lo"
	"github.com/wrouesnel/vault-automation-client/pkg/templating"
	"github.com/wrouesnel/vault-automation-client/pkg/vaultutil/unsealer"
	"github.com/wrouesnel/vault-automation-client/version"
	"go.uber.org/zap"
)

type Options struct {
	Logging struct {
		Level  string `help:"logging level" default:"warning"`
		Format string `help:"logging format (${enum})" enum:"console,json" default:"console"`
	} `embed:"" prefix:"logging."`

	Version bool `help:"Print the version and exit"`

	Unsealer   unsealer.UnsealerCommand  `cmd:"" help:"Start the Vault Unsealer agent"`
	ReadEnvVar templating.ReadEnvCommand `cmd:"" help:"Read environment variable to file"`
}

type LaunchArgs struct {
	StdIn  io.Reader
	StdOut io.Writer
	StdErr io.Writer
	Env    map[string]string
	Args   []string
}

// Entrypoint implements the actual functionality of the program so it can be called inline from testing.
// env is normally passed the environment variable array.
//nolint:funlen,gocognit,gocyclo,cyclop,maintidx
func Entrypoint(args LaunchArgs) int {
	var err error
	options := Options{}

	deferredLogs := []string{}

	// Command line parsing can now happen
	parser := lo.Must(kong.New(&options, kong.Description(version.Description)))
	ctx, err := parser.Parse(args.Args)
	if err != nil {
		_, _ = fmt.Fprintf(args.StdErr, "Argument error: %s", err.Error())
		return 1
	}

	// Initialize logging as soon as possible
	logConfig := zap.NewProductionConfig()
	if err := logConfig.Level.UnmarshalText([]byte(options.Logging.Level)); err != nil {
		deferredLogs = append(deferredLogs, err.Error())
	}
	logConfig.Encoding = options.Logging.Format

	logger, err := logConfig.Build()
	if err != nil {
		// Error unhandled since this is a very early failure
		for _, line := range deferredLogs {
			_, _ = io.WriteString(args.StdErr, line)
		}
		_, _ = io.WriteString(args.StdErr, "Failure while building logger")
		return 1
	}

	// Install as the global logger
	zap.ReplaceGlobals(logger)

	logger.Info("Launched with command line", zap.Strings("cmdline", args.Args))

	if options.Version {
		lo.Must(fmt.Fprintf(args.StdOut, "%s", version.Version))
		return 0
	}

	appCtx, cancelFn := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)

	go func() {
		for sig := range sigCh {
			logger.Info("Caught signal", zap.String("signal", sig.String()))
			cancelFn()
			return
		}
	}()

	logger = logger.With(zap.String("command", ctx.Command()))

	logger.Info("Starting command")
	switch ctx.Command() {
	case "unsealer <vault-endpoint> <vault-instance>":
		err = unsealer.UnsealerEntrypoint(appCtx, &options.Unsealer)
	case "read-env-var <name> <output>":
		err = templating.ReadEnvEntrypoint(appCtx, &options.ReadEnvVar)
	default:
		logger.Error("Command not implemented")
	}

	logger.Debug("Finished command")
	if err != nil {
		logger.Error("Command exited with error", zap.Error(err))
		return 1
	}

	return 0
}
