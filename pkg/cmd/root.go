package cmd

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/eviltomorrow/canary/internal/conf"
	"github.com/eviltomorrow/canary/internal/server"
	"github.com/eviltomorrow/canary/pkg/zlog"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var rootCmd = &cobra.Command{
	Use:   "canary-server",
	Short: "",
	Long:  "  \r\nCanary-server is running",
	Run: func(cmd *cobra.Command, args []string) {
		zlog.Info("Prepare to startup canary", zap.String("conf", cfg.String()))

		registerCleanFunc(server.ShutdownGRPC)
		if err := server.StartupGRPC(); err != nil {
			zlog.Fatal("Startup GRPC server failure", zap.Error(err))
		}
		blockingUntilTermination()
	},
}

var (
	cleanFuncs []func() error
	path       string
	cfg        = conf.Global
)

func init() {
	rootCmd.CompletionOptions = cobra.CompletionOptions{
		DisableDefaultCmd: true,
	}
	rootCmd.Flags().StringVarP(&path, "config", "c", "config.toml", "Canary's config file")
}

func setLog() {
	global, prop, err := zlog.InitLogger(&zlog.Config{
		Level:            cfg.Log.Level,
		Format:           cfg.Log.Format,
		DisableTimestamp: cfg.Log.DisableTimestamp,
		File: zlog.FileLogConfig{
			Filename:   filepath.Join(cfg.System.RootDir, "log", "data.log"),
			MaxSize:    cfg.Log.MaxSize,
			MaxDays:    30,
			MaxBackups: 30,
		},
		DisableStacktrace: true,
	})
	if err != nil {
		log.Fatalf("[Fatal] Setup log config failure, nest error: %v\r\n", err)
	}
	zlog.ReplaceGlobals(global, prop)
}

func registerCleanFunc(clean func() error) {
	cleanFuncs = append(cleanFuncs, clean)
}

func blockingUntilTermination() {
	var ch = make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
	switch <-ch {
	case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
	case syscall.SIGUSR1:
	case syscall.SIGUSR2:
	default:
	}

	for _, f := range cleanFuncs {
		f()
	}
}

func NewClient() {
	cobra.CheckErr(rootCmd.Execute())
}

func NewServer() {
	if err := cfg.Load(path, nil); err != nil {
		log.Fatalf("[Fatal] Load config failure, nest error: %v\r\n", err)
	}

	setVars := func() {
		server.Host = cfg.Server.Host
		server.Port = cfg.Server.Port
		server.CertsDir = filepath.Join(cfg.System.RootDir, "etc", "certs")

		ServerHost = server.Host
		ServerPort = server.Port
		CertsDir = server.CertsDir
	}
	setLog()
	setVars()
	cobra.CheckErr(rootCmd.Execute())
}
