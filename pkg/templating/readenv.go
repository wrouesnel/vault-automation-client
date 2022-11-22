package templating

import (
	"bytes"
	"context"
	"io"
	"os"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type ReadEnvCommand struct {
	Print  bool   `help:"print env var content to stdout"`
	Name   string `help:"environment variable to read" arg:""`
	Output string `help:"file to output to" arg:""`
}

func ReadEnvEntrypoint(ctx context.Context, rec *ReadEnvCommand) error {
	logger := zap.L().With(zap.String("env_var", rec.Name), zap.String("output", rec.Output))
	content := os.Getenv(rec.Name)
	if len(content) == 0 {
		logger.Warn("Environment variable content appears to be empty!")
	}

	outputFi, err := os.OpenFile(rec.Output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(0777))
	if err != nil {
		return errors.Wrapf(err, "could not open output file: %s", rec.Output)
	}

	contentRdr := bytes.NewBufferString(content)

	var teeWr io.Writer
	if rec.Print {
		teeWr = os.Stdout
	} else {
		teeWr = io.Discard
	}

	rdr := io.TeeReader(contentRdr, teeWr)
	if _, err := io.Copy(outputFi, rdr); err != nil {
		return errors.Wrapf(err, "error writing to output file: %s", rec.Output)
	}

	logger.Info("Successful")

	return nil
}
