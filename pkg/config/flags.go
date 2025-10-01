package config

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type FlagEntity[T any] struct {
	Name           string
	HasShort       bool
	Short          string
	Default        T
	Desc           string
	ViperConfigKey string
}

type FlagKey int

const (
	VerboseFlag FlagKey = iota
	ConfigFlag
	HostFlag
	PortFlag
)

var FlagEntities = map[FlagKey]FlagEntity[any]{
	ConfigFlag: {
		Name:     "config",
		HasShort: true,
		Short:    "c",
		Default:  "",
		Desc:     "config file name",
	},
	VerboseFlag: {
		Name:     "verbose",
		HasShort: false,
		Default:  false,
		Desc:     "enable verbose logging (stderr)",
	},
	HostFlag: {
		Name:           "host",
		HasShort:       true,
		Short:          "H",
		Default:        DefaultAuthHost,
		Desc:           "akashic server host",
		ViperConfigKey: "server.auth.host",
	},
	PortFlag: {
		Name:           "port",
		HasShort:       true,
		Short:          "p",
		Default:        DefaultAuthPort,
		Desc:           "akashic server port",
		ViperConfigKey: "server.auth.port",
	},
}

func RegisterFlags(cmd *cobra.Command) {
	for _, entity := range FlagEntities {
		switch v := entity.Default.(type) {
		case string:
			if entity.HasShort {
				cmd.Flags().StringP(entity.Name, entity.Short, v, entity.Desc)
			} else {
				cmd.Flags().String(entity.Name, v, entity.Desc)
			}
		case int:
			if entity.HasShort {
				cmd.Flags().IntP(entity.Name, entity.Short, v, entity.Desc)
			} else {
				cmd.Flags().Int(entity.Name, v, entity.Desc)
			}
		case bool:
			if entity.HasShort {
				cmd.Flags().BoolP(entity.Name, entity.Short, v, entity.Desc)
			} else {
				cmd.Flags().Bool(entity.Name, v, entity.Desc)
			}
		default:
			panic(fmt.Sprintf("unsupported flag type: %T", v))
		}
	}
}

func GetFlagValue[T any](cmd *cobra.Command, key FlagKey) (T, error) {
	entity := FlagEntities[key]
	var zero T

	switch entity.Default.(type) {
	case string:
		val, err := cmd.Flags().GetString(entity.Name)
		if err != nil {
			return zero, err
		}
		if result, ok := any(val).(T); ok {
			return result, nil
		}
		return zero, fmt.Errorf("flag value type mismatch: expected %T, got string", zero)
	case int:
		val, err := cmd.Flags().GetInt(entity.Name)
		if err != nil {
			return zero, err
		}
		if result, ok := any(val).(T); ok {
			return result, nil
		}
		return zero, fmt.Errorf("flag value type mismatch: expected %T, got int", zero)
	case bool:
		val, err := cmd.Flags().GetBool(entity.Name)
		if err != nil {
			return zero, err
		}
		if result, ok := any(val).(T); ok {
			return result, nil
		}
		return zero, fmt.Errorf("flag value type mismatch: expected %T, got bool", zero)
	default:
		return zero, fmt.Errorf("unsupported flag type for key %v", key)
	}
}

func BindPFlags(cmd *cobra.Command, viper *viper.Viper) error {
	for _, entity := range FlagEntities {
		if entity.ViperConfigKey == "" {
			continue
		}
		if err := viper.BindPFlag(entity.ViperConfigKey, cmd.Flags().Lookup(entity.Name)); err != nil {
			return fmt.Errorf("failed to bind flag %s to viper key %s: %v", entity.Name, entity.ViperConfigKey, err)
		}
	}
	return nil
}
