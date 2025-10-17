package core

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type ConfigEntity[T any] struct {
	Key        string
	Env        string
	Name       string
	Short      string
	Persistent bool
	Default    T
	Desc       string
}

func SetDefaults(viper *viper.Viper, entities []ConfigEntity[any]) {
	for _, e := range entities {
		viper.SetDefault(e.Key, e.Default)
	}
}

func BindFlags(cmd *cobra.Command, viper *viper.Viper, entities []ConfigEntity[any]) error {
	for _, e := range entities {
		if e.Key == "" {
			continue
		}
		flag := cmd.Flags().Lookup(e.Name)
		if flag == nil {
			continue
		}
		if err := viper.BindPFlag(e.Key, flag); err != nil {
			fmt.Printf("Failed to bind flag %s to viper key %s: %v\n", e.Name, e.Key, err)
			return err
		}
	}
	return nil
}

func BindEnvs(viper *viper.Viper, entities []ConfigEntity[any]) error {
	for _, e := range entities {
		if e.Key == "" {
			continue
		}
		if e.Env == "" {
			continue
		}
		if err := viper.BindEnv(e.Key, e.Env); err != nil {
			fmt.Printf("Failed to bind env %s to viper key %s: %v\n", e.Env, e.Key, err)
			return err
		}
	}
	return nil
}

func RegisterFlags(cmd *cobra.Command, entities ...ConfigEntity[any]) {
	for _, e := range entities {
		if e.Name == "" {
			continue
		}
		var flagset *pflag.FlagSet
		if e.Persistent {
			flagset = cmd.PersistentFlags()
		} else {
			flagset = cmd.Flags()
		}
		switch v := e.Default.(type) {
		case string:
			flagset.StringP(e.Name, e.Short, v, e.Desc)
		case bool:
			flagset.BoolP(e.Name, e.Short, v, e.Desc)
		case int:
			flagset.IntP(e.Name, e.Short, v, e.Desc)
		case []string:
			flagset.StringArrayP(e.Name, e.Short, v, e.Desc)
		default:
			fmt.Printf("Unsupported default type for flag %s: %T\n", e.Name, e.Default)
			continue
		}
	}
}
