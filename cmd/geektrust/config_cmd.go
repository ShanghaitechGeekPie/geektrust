package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/ShanghaitechGeekPie/geektrust/internal/config"
	"github.com/ShanghaitechGeekPie/geektrust/internal/storage"
	"os"
)

func cmdConfig(path string, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: geektrust config check|show|migrate")
	}
	switch args[0] {
	case "check", "show":
		if len(args) != 1 {
			return errors.New("unexpected configuration arguments")
		}
		c, e := config.Load(path)
		if e != nil {
			return e
		}
		if args[0] == "check" {
			if e = c.ValidateListeners(); e != nil {
				return e
			}
			for _, key := range c.UnknownFields {
				fmt.Printf("warning: ignored legacy field %s\n", key)
			}
			fmt.Println("configuration valid")
			return nil
		}
		fmt.Printf("config_version = %d\ncontroller = %q\ndeployment = %q\nauth_mode = %q\ndns_strategy = %q\nkeystore = %q\nstate_file = %q\n", c.Version, c.BaseURL, c.Deployment, c.ClientType, c.DNSStrategy, c.Keystore, c.StateFile)
		return nil
	case "migrate":
		fs := flag.NewFlagSet("config migrate", flag.ContinueOnError)
		write := fs.Bool("write", false, "back up and replace configuration after preview")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected migration arguments")
		}
		b, e := config.Migration(path)
		if e != nil {
			return e
		}
		if !*write {
			fmt.Print(string(b))
			return nil
		}
		old, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if e = storage.CreateExclusive(path+".v1.bak", old); e != nil {
			return fmt.Errorf("create migration backup: %w", e)
		}
		if e = storage.WriteAtomic(path, b, 0600); e != nil {
			return e
		}
		if _, e = config.Load(path); e != nil {
			_ = storage.WriteAtomic(path, old, 0600)
			return e
		}
		fmt.Println("configuration migrated; original retained in " + path + ".v1.bak")
		return nil
	default:
		return errors.New("unknown configuration command")
	}
}
