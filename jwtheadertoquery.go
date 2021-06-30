package jwtheadertoquery

import (
	"context"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"
)

// Config the plugin configuration.
type Config struct {
	ParamName       string           `json:"paramName"`
}

// CreateConfig creates a new JWTTransform Config
func CreateConfig() *Config {
	return &Config{}
}

// JWTTransform contains the runtime config
type JWTTransform struct {
	next                    http.Handler
	name                    string
	config                  *Config
}

// New creates a new instance of this plugin
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	if config.ParamName == "" {
		return nil, errors.New("ParamName must be set")
	}

	return &JWTTransform{
		next:                    next,
		name:                    name,
		config:                  config,
	}, nil
}

func (q *JWTTransform) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	qry := req.URL.Query()
        qry.Add(q.config.ParamName, "Patrick")

	req.URL.RawQuery = qry.Encode()
	req.RequestURI = req.URL.RequestURI()

	q.next.ServeHTTP(rw, req)
}
