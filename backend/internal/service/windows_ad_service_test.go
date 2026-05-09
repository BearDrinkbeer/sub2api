//go:build unit

package service

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildWindowsADUserFilterEscapesUsername(t *testing.T) {
	filter := buildWindowsADUserFilter("(sAMAccountName={username})", `alice*)(|(sAMAccountName=*))`)

	require.Contains(t, filter, `alice\2a\29\28|\28sAMAccountName=\2a\29\29`)
	require.NotContains(t, strings.TrimPrefix(filter, "(sAMAccountName="), "alice*)")
}

func TestWindowsADSyntheticEmailUsesReservedDomain(t *testing.T) {
	require.Equal(t, "objectguid-abcd"+WindowsADSyntheticEmailDomain, windowsADSyntheticEmail("objectGUID:abcd"))
}
