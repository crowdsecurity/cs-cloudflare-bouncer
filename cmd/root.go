package cmd

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/crowdsecurity/go-cs-lib/pkg/version"

	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cf"
	"github.com/crowdsecurity/cs-cloudflare-bouncer/pkg/cfg"
)

const (
	DEFAULT_CONFIG_PATH = "/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml"
	name                = "crowdsec-cloudflare-bouncer"
)

func newAPILogger(logDir string, logAPIRequests *bool) (*log.Logger, error) {
	APILogger := log.New()
	if *logAPIRequests {
		f, err := os.OpenFile(
			filepath.Join(logDir, "crowdsec-cloudflare-bouncer-api-calls.log"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		APILogger.SetOutput(f)
		APILogger.Level = log.DebugLevel
	} else {
		APILogger.SetOutput(io.Discard)
	}
	return APILogger, nil
}

func Execute() error {
	// Create go routine per cloudflare account
	// By using channels, after every nth second feed the decisions to each cf routine.
	// Each cf routine maintains it's own IP list and cache.

	configTokens := flag.String("g", "", "comma separated tokens to generate config for")
	configOutputPath := flag.String("o", "", "path to store generated config to")
	configPath := flag.String("c", "", "path to config file")
	onlySetup := flag.Bool("s", false, "only setup the ip lists and rules for cloudflare and exit")
	delete := flag.Bool("d", false, "delete IP lists and firewall rules which are created by the bouncer")
	ver := flag.Bool("version", false, "Display version information and exit")
	logAPIRequests := flag.Bool("lc", false, "logs API requests")
	testConfig := flag.Bool("t", false, "test config and exit")
	showConfig := flag.Bool("T", false, "show full config (.yaml + .yaml.local) and exit")

	flag.Parse()

	if *ver {
		fmt.Print(version.FullString())
		return nil
	}

	if *delete && *onlySetup {
		return fmt.Errorf("conflicting cli arguments, pass only one of '-d' or '-s'")
	}

	if configPath == nil || *configPath == "" {
		*configPath = DEFAULT_CONFIG_PATH
	}

	if configTokens != nil && *configTokens != "" {
		cfgTokenString, err := cfg.ConfigTokens(*configTokens, *configPath)
		if err != nil {
			return err
		}
		if configOutputPath != nil && *configOutputPath != "" {
			err := os.WriteFile(*configOutputPath, []byte(cfgTokenString), 0664)
			if err != nil {
				return err
			}
			log.Printf("Config successfully generated in %s", *configOutputPath)
		} else {
			fmt.Print(cfgTokenString)
		}
		return nil
	}

	configBytes, err := cfg.MergedConfig(*configPath)
	if err != nil {
		return fmt.Errorf("unable to read config file: %w", err)
	}

	if *showConfig {
		fmt.Println(string(configBytes))
		return nil
	}

	conf, err := cfg.NewConfig(bytes.NewReader(configBytes))
	if err != nil {
		return fmt.Errorf("unable to parse config: %w", err)
	}

	if *testConfig {
		log.Info("config is valid")
		return nil
	}

	if *delete || *onlySetup {
		log.SetOutput(os.Stdout)
	}

	APILogger, err := newAPILogger(conf.Logging.LogDir, logAPIRequests)
	if err != nil {
		return err
	}

	var csLAPI *csbouncer.StreamBouncer

	zoneLocks := make([]cf.ZoneLock, 0)
	for _, account := range conf.CloudflareConfig.Accounts {
		for _, zone := range account.ZoneConfigs {
			zoneLocks = append(zoneLocks, cf.ZoneLock{ZoneID: zone.ID, Lock: &sync.Mutex{}})
		}
	}

	group, ctx := errgroup.WithContext(context.Background())
	// lapiStreams are used to forward the decisions to all the workers
	lapiStreams := make([]chan *models.DecisionsStreamResponse, 0)
	APICountByToken := make(map[string]*uint32)

	for _, account := range conf.CloudflareConfig.Accounts {
		lapiStream := make(chan *models.DecisionsStreamResponse)
		lapiStreams = append(lapiStreams, lapiStream)

		var tokenCallCount uint32 = 0
		// we want same reference of tokenCallCount per account token
		if _, ok := APICountByToken[account.Token]; !ok {
			APICountByToken[account.Token] = &tokenCallCount
		}

		worker := cf.CloudflareWorker{
			Account:         account,
			APILogger:       APILogger,
			Ctx:             ctx,
			ZoneLocks:       zoneLocks,
			LAPIStream:      lapiStream,
			UpdateFrequency: conf.CloudflareConfig.UpdateFrequency,
			CFStateByAction: make(map[string]*cf.CloudflareState),
			TokenCallCount:  APICountByToken[account.Token],
		}
		if *onlySetup {
			group.Go(func() error {
				var err error
				worker.CFStateByAction = nil
				err = worker.Init()
				if err != nil {
					return err
				}
				err = worker.SetUpCloudflareResources()
				return err
			})
		} else if *delete {
			group.Go(func() error {
				var err error
				err = worker.Init()
				if err != nil {
					return err
				}
				err = worker.DeleteExistingIPList()
				return err
			})
		} else {
			group.Go(func() error {
				err := worker.Run()
				return err
			})
		}
	}

	if !*onlySetup && !*delete {
		log.Infof("Starting %s %s", name, version.String())
		csLAPI = &csbouncer.StreamBouncer{
			APIKey:         conf.CrowdSecLAPIKey,
			APIUrl:         conf.CrowdSecLAPIUrl,
			TickerInterval: conf.CrowdsecUpdateFrequencyYAML,
			UserAgent:      fmt.Sprintf("%s/%s", name, version.String()),
			Opts: apiclient.DecisionsStreamOpts{
				Scopes:                 "ip,range,as,country",
				ScenariosNotContaining: strings.Join(conf.ExcludeScenariosContaining, ","),
				ScenariosContaining:    strings.Join(conf.IncludeScenariosContaining, ","),
				Origins:                strings.Join(conf.OnlyIncludeDecisionsFrom, ","),
			},
			CertPath: conf.CertPath,
			KeyPath:  conf.KeyPath,
			CAPath:   conf.CAPath,
		}
		if err := csLAPI.Init(); err != nil {
			return err
		}
		group.Go(func() error {
			group.Go(func() error {
				csLAPI.Run(ctx)
				return fmt.Errorf("crowdsec LAPI stream has stopped")
			})
			group.Go(func() error {
				for {
					// broadcast decision to each worker
					select {
					case decisions := <-csLAPI.Stream:
						for _, lapiStream := range lapiStreams {
							stream := lapiStream
							go func() { stream <- decisions }()
						}
					case <-ctx.Done():
						return ctx.Err()
					}
				}
			})
			<-ctx.Done()
			return ctx.Err()
		})
	}

	if conf.PrometheusConfig.Enabled {
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			log.Error(http.ListenAndServe(net.JoinHostPort(conf.PrometheusConfig.ListenAddress, conf.PrometheusConfig.ListenPort), nil))
		}()
	}

	apiCallCounterWindow := time.NewTicker(time.Second)
	go func() {
		for {
			<-apiCallCounterWindow.C
			for token := range APICountByToken {
				atomic.SwapUint32(APICountByToken[token], 0)
			}
		}
	}()

	if err := group.Wait(); err != nil {
		return err
	}
	if *delete {
		log.Info("deleted all cf config")
	}
	if *onlySetup {
		log.Info("setup complete")
	}
	return nil
}
