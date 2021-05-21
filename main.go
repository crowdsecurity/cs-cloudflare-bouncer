package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"sync"
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

func workerDeaths(workerTombs []*tomb.Tomb) {
	for {
		workerDied := false
		for _, tomb := range workerTombs {
			if !tomb.Alive() {
				workerDied = true
				break
			}
		}
		// if any  worker dies, kill all the rest of the workers
		if workerDied {
			for _, tomb := range workerTombs {
				tomb.Kill(errors.New("peer worker died"))
			}
			return
		}

	}
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
		zoneLocks := make([]ZoneLock, 0)
		for _, account := range conf.CloudflareConfig.Accounts {
			for _, zone := range account.Zones {
				zoneLocks = append(zoneLocks, ZoneLock{ZoneID: zone.ID, Lock: &sync.Mutex{}})
			}
		}

		// lapiStreams are used to forward the decisions to all the workers
		lapiStreams := make([]chan *models.DecisionsStreamResponse, 0)
		workerTombs := make([]*tomb.Tomb, 0)
		var lapiStreamTombs []*tomb.Tomb

		for _, account := range conf.CloudflareConfig.Accounts {
			lapiStream := make(chan *models.DecisionsStreamResponse)
			lapiStreams = append(lapiStreams, lapiStream)
			worker := CloudflareWorker{
				Account:         account,
				Ctx:             ctx,
				ZoneLocks:       zoneLocks,
				LAPIStream:      lapiStream,
				IPListName:      account.IPListName,
				UpdateFrequency: conf.CloudflareConfig.UpdateFrequency,
			}
			var workerTomb tomb.Tomb
			workerTomb.Go(func() error {
				err := worker.Run()
				return err
			})
			workerTombs = append(workerTombs, &workerTomb)
		}

		var workerHealth tomb.Tomb
		workerHealth.Go(func() error {
			workerDeaths(workerTombs)
			return nil
		})

		for {
			select {
			case decisions := <-csLapi.Stream:
				// broadcast decision to each worker
				lapiStreamTombs = make([]*tomb.Tomb, 0)
				for _, lapiStream := range lapiStreams {
					lapiStream := lapiStream
					var lapiStreamTomb tomb.Tomb
					lapiStreamTomb.Go(func() error {
						lapiStream <- decisions
						return nil
					})
					lapiStreamTombs = append(lapiStreamTombs, &lapiStreamTomb)
				}

			case <-workerHealth.Dead():
				// at this point all workers are dead, so kill all the lapiStream routines, since
				// no worker is listening
				for _, lapiStreamTomb := range lapiStreamTombs {
					lapiStreamTomb.Kill(errors.New("the listening worker died"))
				}
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
