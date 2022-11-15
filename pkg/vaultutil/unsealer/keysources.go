package unsealer

import (
	"fmt"
)

const (
	KeySourceFile       = "file"
	KeySourceKubernetes = "k8s"
	KeySourceVault      = "vault"
)

type KeySourceErr struct {
	msg string
}

func (k KeySourceErr) Error() string {
	return fmt.Sprintf("KeySourceErr: %s", k.msg)
}
