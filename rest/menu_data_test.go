package rest

import (
	"context"
	"testing"

	"github.com/nauticana/keel/port"
)

type menuRows struct {
	port.TableService
	rows []any
}

func (m menuRows) Get(context.Context, int64, int, map[string]any, string) ([]any, error) {
	return m.rows, nil
}

type menuDB struct{ port.DatabaseRepository }

func (menuDB) GetTableService(name string) port.TableService {
	if name == "application_menu" {
		return menuRows{rows: []any{map[string]any{"Id": "setup", "Caption": "Setup", "Icon": "settings"}}}
	}
	return menuRows{rows: []any{map[string]any{"MenuId": "setup", "ItemId": "users", "Caption": "Users", "RestUri": "user_account", "Icon": "group"}}}
}

func TestGetMenuDataCarriesIcons(t *testing.T) {
	menus, err := (&RestService{db: menuDB{}}).GetMenuData(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(menus) != 1 || menus[0].Icon != "settings" || len(menus[0].ApplicationMenuItems) != 1 || menus[0].ApplicationMenuItems[0].Icon != "group" {
		t.Fatalf("menus = %+v", menus)
	}
}
