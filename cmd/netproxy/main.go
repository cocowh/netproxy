package main

import (
	"context"
	"fmt"
	"os"

	"github.com/cocowh/netproxy/internal/core/app"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "netproxy",
		Short: "NetProxy is a high performance network proxy",
		Run:   run,
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) {
	application, err := app.New(cfgFile)
	if err != nil {
		fmt.Printf("Failed to initialize application: %v\n", err)
		os.Exit(1)
	}

	if err := application.Run(context.Background()); err != nil {
		os.Exit(1)
	}
}
