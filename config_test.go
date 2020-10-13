package tlsconfig

import (
	"reflect"
	"strings"
	"testing"
)

func TestConfig_struct_tags(t *testing.T) {
	// Check that all items have all the expected struct tags and they are not reused
	expectedTags := []string{"yaml", "json"}
	seen := make(map[string]map[string]bool) // tagName => contents => bool
	for _, tagName := range expectedTags {
		seen[tagName] = make(map[string]bool)
	}

	r := reflect.TypeOf(Config{})
	for i := 0; i < r.NumField(); i++ {
		field := r.Field(i)
		t.Logf("field %s", field.Name)
		var lastName string
		for _, tagName := range expectedTags {
			tag := field.Tag.Get(tagName)
			if tag == "" {
				t.Errorf("field %s: does not have expected struct tag %s", field.Name, tagName)
				continue
			}
			name := strings.Split(tag, ",")[0]
			if name == "-" {
				continue
			}
			// All different encodings must have the same field name for consistency
			if lastName != "" && name != lastName {
				t.Errorf("field %s: inconsistent naming for tag %s: got %s, expected %s",
					field.Name, tagName, name, lastName)
			}
			lastName = name
			// Catch copy-paste errors
			if seen[tagName][name] {
				t.Errorf("field %s: already seen this struct tag %s name: %s",
					field.Name, tagName, name)
				continue
			}
			seen[tagName][name] = true
		}
	}
}
