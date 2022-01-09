package cmd

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/eviltomorrow/canary/pkg/client"
	"github.com/eviltomorrow/canary/pkg/system"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version about canary",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if err := cfg.Load(path, nil); err != nil {
			log.Fatalf("[Fatal] Load config failure, nest error: %v\r\n", err)
		}
		printClientVersion()
		printServerVersion()
	},
}

var (
	ServerName = "www.roigo.top"
	timeout    = 10 * time.Second
)

func init() {
	versionCmd.Flags().StringVarP(&path, "config", "c", "config.toml", "Canary's config file")
	ctlCmd.AddCommand(versionCmd)
	serverCmd.AddCommand(versionCmd)
}

func printClientVersion() {
	var buf bytes.Buffer
	buf.WriteString("Client: \r\n")
	buf.WriteString(fmt.Sprintf("   Canary Version (Current): %s\r\n", system.CurrentVersion))
	buf.WriteString(fmt.Sprintf("   Go Version: %v\r\n", system.GoVersion))
	buf.WriteString(fmt.Sprintf("   Go OS/Arch: %v\r\n", system.GoOSArch))
	buf.WriteString(fmt.Sprintf("   Git Sha: %v\r\n", system.GitSha))
	buf.WriteString(fmt.Sprintf("   Git Tag: %v\r\n", system.GitTag))
	buf.WriteString(fmt.Sprintf("   Git Branch: %v\r\n", system.GitBranch))
	buf.WriteString(fmt.Sprintf("   Build Time: %v\r\n", system.BuildTime))
	fmt.Println(buf.String())
}

func printServerVersion() {
	if isServer {
		return
	}
	var buf bytes.Buffer
	buf.WriteString("Server: \r\n")

	creds, err := client.WithTLS(ServerName, filepath.Join(cfg.System.RootDir, "certs", "ca.crt"), filepath.Join(cfg.System.RootDir, "certs", "client.pem"), filepath.Join(cfg.System.RootDir, "certs", "client.crt"))
	if err != nil {
		buf.WriteString(fmt.Sprintf("   [Fatal] %v\r\n", err))
		fmt.Println(buf.String())
		os.Exit(0)
	}

	stub, close, err := client.NewSystem(cfg.Server.Host, cfg.Server.Port, creds, timeout)
	if err != nil {
		buf.WriteString(fmt.Sprintf("   [Fatal] %v\r\n", err))
		fmt.Println(buf.String())
		os.Exit(0)
	}
	defer close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resp, err := stub.Version(ctx, &emptypb.Empty{})
	if err != nil {
		buf.WriteString(fmt.Sprintf("   [Fatal] %v\r\n", err))
		fmt.Println(buf.String())
		os.Exit(0)
	}
	buf.WriteString(fmt.Sprintf("   Canary Version (Current): %s\r\n", resp.CurrentVersion))
	buf.WriteString(fmt.Sprintf("   Go Version: %v\r\n", resp.GoVersion))
	buf.WriteString(fmt.Sprintf("   Go OS/Arch: %v\r\n", resp.GoOsArch))
	buf.WriteString(fmt.Sprintf("   Git Sha: %v\r\n", resp.GitSha))
	buf.WriteString(fmt.Sprintf("   Git Tag: %v\r\n", resp.GitTag))
	buf.WriteString(fmt.Sprintf("   Git Branch: %v\r\n", resp.GitBranch))
	buf.WriteString(fmt.Sprintf("   Build Time: %v\r\n", resp.BuildTime))
	fmt.Println(buf.String())
}
