package main

import (
	"errors"

	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	cmd.AddCommand(cmdConfig)
	cmdConfig.AddCommand(cmdConfigGet)
	cmdConfig.AddCommand(cmdConfigSet)
	cmdConfig.AddCommand(cmdConfigShow)
}

var (
	cmdConfig = &cobra.Command{
		Use:   "config",
		Short: "Configure your DSS instance",
	}

	cmdConfigGet = &cobra.Command{
		Use:     "get",
		Short:   "Get a config value",
		Example: "  dss config get nameservers",
		Args:    cobra.ExactArgs(1),
		Run: func(command *cobra.Command, args []string) {
			cfgVal, err := cfg.Get(args[0])
			if err != nil {
				log.Fatal().Err(err).Msg("could not get config")
			}

			printToConsole(args[0] + ": " + cast.ToString(cfgVal))
		},
	}

	cmdConfigSet = &cobra.Command{
		Use:     "set",
		Short:   "Set a config value",
		Example: "  dss config set nameservers 8.8.8.8,9.9.9.9",
		Args:    cobra.ExactArgs(2),
		Run: func(command *cobra.Command, args []string) {
			if err := cfg.Set(args[0], args[1]); err != nil {
				log.Fatal().Err(err).Msg("could not set config")
			}

			printToConsole("Successfully set " + args[0] + " as " + args[1])
		},
	}

	cmdConfigShow = &cobra.Command{
		Use:     "show",
		Short:   "Print full config",
		Example: "  dss config show",
		Args:    cobra.ExactArgs(0),
		Run: func(command *cobra.Command, args []string) {
			printToConsole(cfg)
		},
	}
)

type Config struct {
	Nameservers []string `json:"nameservers" yaml:"nameservers"`
}

func (c *Config) Get(key string) (interface{}, error) {
	switch key {
	case "nameservers":
		return viper.Get(key), nil
	default:
		return "", errors.New("invalid config key")
	}
}

func (c *Config) Set(key string, value string) error {
	switch key {
	case "nameservers":
		viper.Set(key, value)
	default:
		return errors.New("invalid config key")
	}

	return viper.WriteConfig()
}
