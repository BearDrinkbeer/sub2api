//go:build integration

package repository

import (
	"context"
	"fmt"
	"testing"

	"github.com/Wei-Shaw/sub2api/migrations"
	"github.com/stretchr/testify/require"
)

func TestWindowsADMigrationPreservesExistingProviders(t *testing.T) {
	for _, existingProvider := range []string{"windows_ad", "dingtalk"} {
		t.Run(existingProvider, func(t *testing.T) {
			tx := testTx(t)
			ctx := context.Background()
			_, err := tx.ExecContext(ctx, `CREATE TEMP TABLE users (
				id BIGINT PRIMARY KEY,
				signup_source VARCHAR(20) NOT NULL
			) ON COMMIT DROP`)
			require.NoError(t, err)
			_, err = tx.ExecContext(ctx, "INSERT INTO users (id, signup_source) VALUES (1, $1)", existingProvider)
			require.NoError(t, err)
			tables := []string{"auth_identities", "auth_identity_channels", "pending_auth_sessions", "user_provider_default_grants"}
			for _, table := range tables {
				_, err = tx.ExecContext(ctx, fmt.Sprintf(`CREATE TEMP TABLE %s (
					id BIGINT PRIMARY KEY,
					provider_type VARCHAR(20) NOT NULL,
					provider_key TEXT NOT NULL,
					provider_subject TEXT NOT NULL
				) ON COMMIT DROP`, table))
				require.NoError(t, err)
				_, err = tx.ExecContext(ctx, fmt.Sprintf("INSERT INTO %s VALUES (1, $1, $2, $3)", table),
					existingProvider, "DC=intra,DC=example,DC=cn", "objectguid:existing")
				require.NoError(t, err)
			}

			// Old AD databases must survive the intervening DingTalk constraints;
			// main databases with the original migrations go straight to 247.
			names := []string{"247_allow_windows_ad_auth_provider_type.sql"}
			if existingProvider == "windows_ad" {
				names = append([]string{"136_add_dingtalk_provider_type.sql", "140_extend_user_provider_default_grants_check.sql"}, names...)
			}
			for _, name := range names {
				content, err := migrations.FS.ReadFile(name)
				require.NoError(t, err)
				_, err = tx.ExecContext(ctx, string(content))
				require.NoError(t, err, name)
			}

			var source string
			require.NoError(t, tx.QueryRowContext(ctx, "SELECT signup_source FROM users WHERE id = 1").Scan(&source))
			require.Equal(t, existingProvider, source)
			for _, table := range tables {
				var provider, key, subject string
				require.NoError(t, tx.QueryRowContext(ctx, fmt.Sprintf("SELECT provider_type, provider_key, provider_subject FROM %s WHERE id = 1", table)).Scan(&provider, &key, &subject))
				require.Equal(t, existingProvider, provider)
				require.Equal(t, "DC=intra,DC=example,DC=cn", key)
				require.Equal(t, "objectguid:existing", subject)
				for i, newProvider := range []string{"windows_ad", "dingtalk"} {
					_, err = tx.ExecContext(ctx, fmt.Sprintf("INSERT INTO %s VALUES ($1, $2, 'new-key', 'new-subject')", table), i+2, newProvider)
					require.NoError(t, err, table)
				}
			}
		})
	}
}
