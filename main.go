package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/coreos/go-systemd/daemon"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

var t tomb.Tomb

func HandleSignals(ctx context.Context) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM)
	exitChan := make(chan int)
	go func() {
		for {
			s := <-signalChan
			switch s {
			case syscall.SIGTERM:
				exitChan <- 0
			}
		}
	}()
	code := <-exitChan
	log.Infof("Shutting down cloudflare-bouncer service")
	os.Exit(code)
}

func main() {

	// Create go routine per cloudflare account
	// By using channels, after every nth second feed the decisions to each cf routine.
	// Each cf routine maintains it's own IP list and cache.

	configPath := flag.String("c", "", "path to config file")
	flag.Parse()

	if configPath == nil || *configPath == "" {
		log.Fatalf("config file required")
	}

	// configPath := "./cfg.yaml"
	ctx := context.Background()
	conf, err := NewConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	csLapi := &csbouncer.StreamBouncer{
		APIKey:         conf.CrowdSecLAPIKey,
		APIUrl:         conf.CrowdSecLAPIUrl,
		TickerInterval: conf.CrowdsecUpdateFrequencyYAML,
	}

	if err := csLapi.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	go csLapi.Run()

	t.Go(func() error {
		lapiStreams := make([]chan *models.DecisionsStreamResponse, 0)
		workerDeaths := make(chan struct{})

		for _, account := range conf.CloudflareConfig.Accounts {
			lapiStream := make(chan *models.DecisionsStreamResponse)
			lapiStreams = append(lapiStreams, lapiStream)
			account := account
			worker := CloudflareWorker{Account: account, Ctx: ctx, LAPIStream: lapiStream, DeathChannel: workerDeaths, IPListName: account.IPListName, UpdateFrequency: conf.CloudflareConfig.UpdateFrequency}
			go worker.Run()
		}
		for {
			select {
			case decisions := <-csLapi.Stream:
				// broadcast decision to each worker
				for _, lapiStream := range lapiStreams {
					lapiStream := lapiStream
					go func() {
						lapiStream <- decisions
					}()
				}

			case <-workerDeaths:
				return errors.New("halting due to worker death")
			}
		}
	})
	if conf.Daemon {
		sent, err := daemon.SdNotify(false, "READY=1")
		if !sent && err != nil {
			log.Fatalf("failed to notify: %v", err)
		}
		HandleSignals(ctx)
	}

	err = t.Wait()
	if err != nil {
		log.Fatalf("process return with error: %s", err)
	}
}
