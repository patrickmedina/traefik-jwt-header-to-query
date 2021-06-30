package traefik_jwt_header_to_query

import (
	"context"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"
	"fmt"
	"bytes"
)

// Config the plugin configuration.
type Config struct {
	Path										string			`json:"path"`
	HeaderName			string			`json:"headerName"`
	HeaderPrefix			string			`json:"headerPrefix"`
	ParamName				string			`json:"paramName"`
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

	if len(config.Path) == 0 || config.Path == "" {
		config.Path = "/"
	}

	if len(config.HeaderName) == 0 || config.HeaderName == "" {
		config.HeaderName = "Authorization"
	}

	if len(config.HeaderPrefix) == 0 || config.HeaderPrefix == "" {
		config.HeaderPrefix = ""
	}

	if len(config.ParamName) == 0 || config.ParamName == "" {
		config.ParamName = "jwt"
	}

	return &JWTTransform{
		next:                    next,
		name:                    name,
		config:                  config,
	}, nil
}

func (q *JWTTransform) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Only process requests that matches the given path in config
	if req.URL.Path != q.config.Path {
		// Pass-through
		q.next.ServeHTTP(rw, req)
		return
	}
	// Get current query params
	qry := req.URL.Query()
	// Get header value based on the given HeaderName config
	headerValue := req.Header.Get(q.config.HeaderName)
	// Get the token
	token := strings.TrimPrefix(headerValue, q.config.HeaderPrefix)
	token = strings.TrimSpace(token)
	// Add the token as query parameter
	qry.Add(q.config.ParamName, token)
  // Strip the header
	req.Header.Del(q.config.HeaderName)
	// Apply the added query params to the request
	req.URL.RawQuery = qry.Encode()
	req.RequestURI = req.URL.RequestURI()
  // Execute next middleware
	q.next.ServeHTTP(rw, req)
}
