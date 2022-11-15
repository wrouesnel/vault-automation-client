package unsealer

import (
	"bufio"
	"github.com/pkg/errors"
	"io"
	"os"
)

type FileSource struct {
	FilePath string `mapstructure:"path" help:"Path to the file with the unseal-key'"`
}

func (fu *FileSource) GetUnsealKey() (string, error) {
	f, err := os.Open(fu.FilePath)
	if err != nil {
		return "", errors.Wrapf(err, "FileSource: %s", fu.FilePath)
	}

	bio := bufio.NewReader(f)
	key, err := bio.ReadString('\n')
	if err != nil {
		if !errors.Is(err, io.EOF) {
			return "", errors.Wrapf(err, "FileSource: %s", fu.FilePath)
		}
	}

	return key, nil
}
