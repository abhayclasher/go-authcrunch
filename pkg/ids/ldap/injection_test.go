// Copyright 2022 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ldap

import (
	"github.com/go-ldap/ldap/v3"
	"strings"
	"testing"
)

// Test the LDAP injection vulnerability
func TestLDAPInjection(t *testing.T) {
	// Test case 1: wildcard injection
	username := "*"
	filterTemplate := "(&(sAMAccountName=%s)(objectclass=user))"
	
	// Vulnerable way (current code)
	vulnerable := strings.ReplaceAll(filterTemplate, "%s", username)
	// Result: (&(sAMAccountName=*)(objectclass=user))
	// This matches ALL users, not just one
	
	// Fixed way
	escaped := ldap.EscapeFilter(username)
	fixed := strings.ReplaceAll(filterTemplate, "%s", escaped)
	// Result: (&(sAMAccountName=\2a)(objectclass=user))
	// This matches only a user literally named "*"
	
	if vulnerable == fixed {
		t.Fatal("vulnerable and fixed should be different")
	}
	
	// Make sure the fix actually escapes the wildcard
	if !strings.Contains(fixed, "\\2a") {
		t.Fatalf("expected \\2a in fixed filter, got: %s", fixed)
	}
	
	t.Logf("vulnerable: %s", vulnerable)
	t.Logf("fixed:      %s", fixed)
}

// Test that ldap.EscapeFilter handles dangerous characters
func TestEscapeFilter(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"admin", "admin"},
		{"*", "\\2a"},
		{"(", "\\28"},
		{")", "\\29"},
		{"admin*", "admin\\2a"},
		{"admin*))(&(uid=*", "admin\\2a\\29\\29\\28&\\28uid=\\2a"},
	}
	
	for _, c := range cases {
		result := ldap.EscapeFilter(c.input)
		if result != c.expected {
			t.Errorf("EscapeFilter(%q) = %q, want %q", c.input, result, c.expected)
		}
	}
}
