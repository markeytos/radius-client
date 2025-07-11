/*
Copyright © 2025 Keytos alan@keytos.io
*/
package cmd

import (
	"errors"
	"time"
)

func retry(fn func() error) error {
	var errs error

	retries++
	for retries > 0 {
		err := fn()
		if err == nil {
			return nil
		}
		errs = errors.Join(errs, err)
		retries--
		time.Sleep(retryInterval)
	}

	return errs
}
