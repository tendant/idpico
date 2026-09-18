// Command idpicoctl manages users, groups, clients and signing keys directly in
// the store, for scripts and Makefiles that should not go through the admin
// UI. It opens the same database the server uses; stop the server first when
// using the JSON file driver.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tendant/idpico/internal/crypto"
	"github.com/tendant/idpico/internal/store"
	"github.com/tendant/idpico/internal/store/file"
	"github.com/tendant/idpico/internal/store/sqlite"
)

const usage = `Usage: idpicoctl [global flags] <resource> <command> [args]

Global flags:
  -driver    sqlite (default) or file
  -data-dir  data directory (default ./data)
  -dsn       SQLite database path (default <data-dir>/idpico.db)

Resources and commands:
  user    list
          add <email> [-name NAME] [-password PW] [-admin] [-verified] [-inactive]
          passwd <email> <password>
          set-admin <email> true|false
          delete <email>
  group   list
          add <name> [-desc TEXT]
          delete <name>
          members <name>
          add-member <name> <email>
          remove-member <name> <email>
  client  list
          add <id> -redirect URI [-redirect URI ...] [-name NAME] [-public] [-skip-consent] [-scopes "a b"]
          reset-secret <id>
          delete <id>
  key     list
          rotate [-grace DURATION]

Examples:
  idpicoctl user add alice@example.com -name Alice -password s3cret-pass -admin
  idpicoctl group add admins && idpicoctl group add-member admins alice@example.com
  idpicoctl client add my-app -redirect http://localhost:3000/callback
`

func main() {
	global := flag.NewFlagSet("idpicoctl", flag.ContinueOnError)
	global.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	driver := global.String("driver", "sqlite", "store driver: sqlite or file")
	dataDir := global.String("data-dir", "./data", "data directory")
	dsn := global.String("dsn", "", "SQLite database path")
	if err := global.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	ctx := context.Background()
	st, keys, err := openStore(ctx, *driver, *dataDir, *dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer st.Close()

	app := &app{store: st, keys: keys, out: os.Stdout}
	if err := app.run(ctx, global.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func openStore(ctx context.Context, driver, dataDir, dsn string) (store.Store, *crypto.KeyService, error) {
	switch driver {
	case "sqlite":
		if dsn == "" {
			dsn = filepath.Join(dataDir, "idpico.db")
		}
		s, err := sqlite.NewStore(ctx, dsn)
		if err != nil {
			return nil, nil, err
		}
		return s, crypto.NewKeyService(s.Keys()), nil
	case "file":
		s, err := file.NewStore(dataDir)
		if err != nil {
			return nil, nil, err
		}
		return s, crypto.NewKeyService(file.NewKeyRepository(dataDir)), nil
	default:
		return nil, nil, fmt.Errorf("unknown driver %q (expected sqlite or file)", driver)
	}
}
