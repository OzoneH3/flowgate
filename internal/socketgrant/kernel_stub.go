//go:build !socketprototype

package socketgrant

import "errors"

func OpenKernel() (Backend, error) {
	return nil, errors.New("socket gate requires isolated socketprototype build")
}
