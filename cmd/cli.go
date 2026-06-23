package main

import (
	"context"
	"flag"
	"github.com/sirupsen/logrus"
	"github.com/w4l1dcode/ossti2sentinel/config"
	"github.com/w4l1dcode/ossti2sentinel/pkg/feeds/abusech"
	"github.com/w4l1dcode/ossti2sentinel/pkg/feeds/extensions"
	msSentinel "github.com/w4l1dcode/ossti2sentinel/pkg/sentinel"
	"net/http"
	"time"
)

func main() {
	ctx := context.Background()

	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	confFile := flag.String("config", "ossti2sentinel.yml", "The YAML configuration file.")
	cliLogLevel := flag.String("log", "", "The required log level, overwrites config log level.")
	flag.Parse()

	conf := config.Config{}
	if err := conf.Load(*confFile); err != nil {
		logger.WithError(err).WithField("config", *confFile).Fatal("failed to load configuration")
	}

	if err := conf.Validate(); err != nil {
		logger.WithError(err).WithField("config", *confFile).Fatal("invalid configuration")
	}

	requiredLogLevel := conf.Log.Level
	if *cliLogLevel != "" {
		logger.Info("setting log level from cli flags")
		requiredLogLevel = *cliLogLevel
	}
	logrusLevel, err := logrus.ParseLevel(requiredLogLevel)
	if err != nil {
		logger.WithError(err).Error("invalid log level provided")
		logrusLevel = logrus.InfoLevel
	}
	logger.WithField("level", logrusLevel.String()).Info("set log level")
	logger.SetLevel(logrusLevel)

	// ---
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// ---

	logger.Info("fetching MalwareBazaar recent SHA256 hashes")
	malwareHashes, err := abusech.FetchMalwareBazaarRecent(ctx, httpClient)
	if err != nil {
		logger.WithError(err).Fatal("could not fetch MalwareBazaar feed")
	}
	logger.WithField("count", len(malwareHashes)).
		Info("fetched MalwareBazaar hashes")

	logger.Info("fetching URLHaus online URL feed")
	urlHausEntries, err := abusech.FetchURLHausOnline(ctx, httpClient)
	if err != nil {
		logger.WithError(err).Fatal("could not fetch URLHaus feed")
	}
	logger.WithField("count", len(urlHausEntries)).
		Info("fetched URLHaus URLs")

	logger.Info("fetching malicious Visual Studio Code extension feed")
	vscodeExtensions, err := extensions.FetchVSCode(ctx, httpClient)
	if err != nil {
		logger.WithError(err).Fatal("could not fetch malicious Visual Studio Code extension feed")
	}
	logger.WithField("count", len(vscodeExtensions)).
		Info("fetched malicious Visual Studio Code extensions")

	logger.Info("fetching malicious browser extension feed")
	browserExtensions, err := extensions.FetchBrowser(ctx, httpClient)
	if err != nil {
		logger.WithError(err).Fatal("could not fetch malicious browser extension feed")
	}
	logger.WithField("count", len(browserExtensions)).
		Info("fetched malicious browser extensions")

	fetchedAt := time.Now()
	allLogs := abusech.BuildLogs(malwareHashes, urlHausEntries, fetchedAt)
	allLogs = append(allLogs, extensions.BuildLogs(vscodeExtensions, browserExtensions, fetchedAt)...)

	sentinel, err := msSentinel.New(logger, msSentinel.Credentials{
		TenantID:       conf.Microsoft.TenantID,
		ClientID:       conf.Microsoft.AppID,
		ClientSecret:   conf.Microsoft.SecretKey,
		SubscriptionID: conf.Microsoft.SubscriptionID,
	})
	if err != nil {
		logger.WithError(err).Fatal("could not create MS Sentinel client")
	}

	logger.WithField("total", len(allLogs)).Info("shipping off ioc's to Sentinel")

	if err := sentinel.SendLogs(ctx, logger,
		conf.Microsoft.DataCollection.Endpoint,
		conf.Microsoft.DataCollection.RuleID,
		conf.Microsoft.DataCollection.StreamName,
		allLogs); err != nil {
		logger.WithError(err).Fatal("could not ship logs to sentinel")
	}

	logger.WithField("total", len(allLogs)).Info("successfully sent logs to sentinel")

}
