//go:build unit

package service

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
)

func TestWindowsADStartTLSSendsServerNameWithVerificationEnabled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	serverName := make(chan string, 1)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- func() error {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return err
			}
			request, err := ber.ReadPacket(conn)
			if err != nil {
				return err
			}
			if len(request.Children) != 2 || request.Children[1].Tag != ldap.ApplicationExtendedRequest {
				return errors.New("expected LDAP StartTLS request")
			}
			response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP response")
			response.AppendChild(request.Children[0])
			result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationExtendedResponse, nil, "StartTLS result")
			result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ldap.LDAPResultSuccess), "result code"))
			result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matched DN"))
			result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnostic message"))
			response.AppendChild(result)
			if _, err := conn.Write(response.Bytes()); err != nil {
				return err
			}
			// Stop after ClientHello; no domain credentials or trusted certificate are needed.
			tlsConn := tls.Server(conn, &tls.Config{
				MinVersion: tls.VersionTLS12,
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					serverName <- hello.ServerName
					return nil, errors.New("ClientHello inspected")
				},
			})
			_ = tlsConn.Handshake()
			return nil
		}()
	}()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	_, err = (LDAPWindowsADAuthenticator{DialTimeout: 5 * time.Second}).Authenticate(context.Background(), config.WindowsADConfig{
		Enabled:  true,
		URL:      "ldap://" + net.JoinHostPort("localhost", port),
		BaseDN:   "DC=example,DC=com",
		StartTLS: true,
	}, "domain-user", "test-password")
	require.Error(t, err)
	select {
	case err := <-serverDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("LDAP StartTLS fixture did not finish")
	}
	select {
	case got := <-serverName:
		require.Equal(t, "localhost", got)
	default:
		t.Fatal("StartTLS did not send ClientHello with the configured server name")
	}
}

func TestBuildWindowsADUserFilterEscapesUsername(t *testing.T) {
	filter := buildWindowsADUserFilter("(sAMAccountName={username})", `alice*)(|(sAMAccountName=*))`)

	require.Contains(t, filter, `alice\2a\29\28|\28sAMAccountName=\2a\29\29`)
	require.NotContains(t, strings.TrimPrefix(filter, "(sAMAccountName="), "alice*)")
}

func TestBuildWindowsADUserFilterSupportsDoubleBracePlaceholder(t *testing.T) {
	filter := buildWindowsADUserFilter("(sAMAccountName={{username}})", "zhangsan")

	require.Equal(t, "(sAMAccountName=zhangsan)", filter)
}

func TestWindowsADSyntheticEmailUsesReservedDomain(t *testing.T) {
	require.Equal(t, "objectguid-abcd"+WindowsADSyntheticEmailDomain, windowsADSyntheticEmail("objectGUID:abcd"))
}

func TestBuildWindowsADUserFilterWithoutPlaceholder(t *testing.T) {
	for _, template := range []string{"(objectClass=user)", "objectClass=user"} {
		require.Equal(t, "(&(objectClass=user)(|(sAMAccountName=alice)(userPrincipalName=alice)))", buildWindowsADUserFilter(template, "alice"))
	}
}
