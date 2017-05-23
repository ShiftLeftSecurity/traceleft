package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ShiftLeftSecurity/traceleft/generator"
)

var handlerConfig string
var handlerTargetDir string
var handlerTemplate string

var genHandlerCmd = &cobra.Command{
	Use:   "gen-handler",
	Short: "Generate bpf handler code from config",
	Run:   cmd,
}

func cmd(cmd *cobra.Command, args []string) {
	if err := generator.GenerateBpfSources(handlerConfig, handlerTemplate, handlerTargetDir); err != nil {
		fmt.Fprintf(os.Stderr, "Failed generating handler code: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.AddCommand(genHandlerCmd)
	genHandlerCmd.Flags().StringVar(&handlerConfig, "handler-config", "./config.json", "handler config")
	genHandlerCmd.Flags().StringVar(&handlerTargetDir, "handler-target-dir", "./battery", "where to place generated handler code")
	genHandlerCmd.Flags().StringVar(&handlerTemplate, "handler-template", "./battery/handler.c.tpl", "handler.c template")
}
