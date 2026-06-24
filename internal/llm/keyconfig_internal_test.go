package llm

import (
	"reflect"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

// TestKeyConfigRequired_FieldsExist pins every keyConfigRequired member to a
// real <X>KeyConfig field on schemas.Key (same rule ValidateKeyConfigs uses),
// so an upstream rename/removal or a typo in the set fails loudly.
func TestKeyConfigRequired_FieldsExist(t *testing.T) {
	t.Parallel()
	for _, provider := range keyConfigRequired {
		found := false
		for field := range reflect.TypeFor[schemas.Key]().Fields() {
			name, isKeyConfig := strings.CutSuffix(field.Name, "KeyConfig")
			if isKeyConfig && strings.EqualFold(name, string(provider)) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("keyConfigRequired provider %q has no <X>KeyConfig field on schemas.Key", provider)
		}
	}
}
