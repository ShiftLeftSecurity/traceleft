package cmd

import (
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	_ "net/http/pprof"
)

var cfgFile string
var pprofListenAddr string

var RootCmd = &cobra.Command{
	Use:   "traceleft",
	Short: "Trace syscalls and network events from arbitrary processes",
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.traceleft.yaml)")
	RootCmd.PersistentFlags().StringVar(&pprofListenAddr, "pprof-listen-addr", "", "listen address for HTTP profiling and instrumentation server")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
		viper.AutomaticEnv()

		if err := viper.ReadInConfig(); err == nil {
			fmt.Println("Using config file:", viper.ConfigFileUsed())
		}
	}

	if pprofListenAddr != "" {
		go func() {
			http.ListenAndServe(pprofListenAddr, nil)
		}()
	}
}
