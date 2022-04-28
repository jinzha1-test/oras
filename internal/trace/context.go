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

package trace

import (
	"context"
	"io/ioutil"

	"github.com/sirupsen/logrus"
)

// loggerKey is the associated key type for logger entry in context.
type loggerKey struct{}

// ContextWithLogger returns a context with logrus log entry.
func ContextWithLogger(ctx context.Context, verbose, debug bool) context.Context {
	log := logrus.New()

	if debug {
		log.SetLevel(logrus.DebugLevel)
	} else if !verbose {
		log.Out = ioutil.Discard
	}

	return context.WithValue(ctx, loggerKey{}, log.WithContext(ctx))
}
