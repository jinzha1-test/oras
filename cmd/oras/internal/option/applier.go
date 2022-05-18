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
package option

import (
	"reflect"

	"github.com/spf13/pflag"
)

// FlagApplier applies flags to a command flag set.
type FlagApplier interface {
	ApplyFlags(*pflag.FlagSet)
}

// ApplyFlags applies applicable fields of the passed-in option pointer to the
// target flag set.
// NOTE: The option argument need to be a pointer to the options, so its value
// is on heap and addressable.
func ApplyFlags(optsPtr interface{}, target *pflag.FlagSet) {
	v := reflect.ValueOf(optsPtr).Elem()
	for i := 0; i < v.NumField(); i++ {
		iface := v.Field(i).Addr().Interface()
		if a, ok := iface.(FlagApplier); ok {
			a.ApplyFlags(target)
		}
	}
}
