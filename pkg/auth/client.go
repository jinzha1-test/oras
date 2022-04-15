/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"context"
	"errors"
)

// Common errors
var (
	ErrNotLoggedIn = errors.New("not logged in")
)

type (
	// LoginSettings represent all the various settings on login.
	LoginSettings struct {
		Context   context.Context
		Hostname  string
		Username  string
		Secret    string
		Insecure  bool
		PlainHTTP bool
		UserAgent string
	}
)

// Client provides authentication operations for remotes.
type Client interface {
	// Login logs in to a remote server identified by the custom options
	Login(settings *LoginSettings) error
	// Logout logs out from a remote server identified by the hostname.
	Logout(ctx context.Context, hostname string) error
}
