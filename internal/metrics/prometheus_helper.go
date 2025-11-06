package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

func shouldRegister(cs ...prometheus.Collector) error {
	var are prometheus.AlreadyRegisteredError
	for _, coll := range cs {
		if err := prometheus.Register(coll); err != nil {
			if !errors.As(err, &are) {
				return err
			}
		}
	}
	return nil
}
