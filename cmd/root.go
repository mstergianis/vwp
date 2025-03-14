/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"os"
	"path"

	"github.com/mstergianis/vwp/pkg/config"
	"github.com/mstergianis/vwp/pkg/pass"
	"github.com/mstergianis/vwp/pkg/vault"
	"github.com/mstergianis/vwp/pkg/xdg"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vwp",
	Short: "",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		configHome, err := xdg.ConfigHome()
		if err != nil {
			return err
		}
		conf, err := config.New(
			path.Join(configHome, "config.yaml"),
			func() pass.Pass { return pass.New("") },
		)
		if err != nil {
			return err
		}

		vwi := vault.New(conf)

		secrets, err := vwi.GetAllSecrets()
		if err != nil {
			return err
		}

		if len(args) > 0 && args[0] == "debug" {
			enc := json.NewEncoder(os.Stdout)
			err = enc.Encode(secrets)
			if err != nil {
				return err
			}
			return
		}

		vwpPassRunner := pass.New("vwp")
		for _, secret := range secrets {
			vwpPassRunner.Add(secret.Password, path.Join(secret.Name, "password"))
			vwpPassRunner.Add(secret.Username, path.Join(secret.Name, "username"))
		}

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.vaultwarden-pass-syncer.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
}
