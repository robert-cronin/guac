package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/certify"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/certifier/datadog"
	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type datadogOneOptions struct {
	graphqlEndpoint string
	headerFile      string
	poll            bool
	interval        time.Duration
	// sets artificial latency on the certifier (optional)
	addedLatency *time.Duration
	batchSize    int
	lastScan     *int
}

var datadogOneCmd = &cobra.Command{
	Use:   "datadog [flags]",
	Short: "Runs the DataDog malicious package certifier once directly",
	Run: func(cmd *cobra.Command, args []string) {
		opts, err := validateDatadogOneFlags(
			viper.GetString("gql-addr"),
			viper.GetString("header-file"),
			viper.GetString("interval"),
			viper.GetString("certifier-latency"),
			viper.GetInt("certifier-batch-size"),
			viper.GetInt("last-scan"),
			viper.GetBool("poll"),
		)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)
		transport := cli.HTTPHeaderTransport(ctx, opts.headerFile, http.DefaultTransport)

		assemblerFunc := ingestor.GetAssembler(ctx, logger, opts.graphqlEndpoint, transport)
		ddCertifier, err := datadog.NewDataDogCertificationParser(ctx, assemblerFunc)
		if err != nil {
			logger.Fatalf("unable to create datadog certifier: %v", err)
		}

		if err := certify.RegisterCertifier(func() certifier.Certifier { return ddCertifier }, certifier.CertifierDataDog); err != nil {
			logger.Fatalf("unable to register datadog certifier: %v", err)
		}

		httpClient := http.Client{Transport: transport}
		gqlclient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)

		packageQuery := root_package.NewPackageQuery(gqlclient, generated.QueryTypeVulnerability, opts.batchSize, 1000, opts.addedLatency, opts.lastScan)

		totalNum := 0
		emit := func(d *processor.Document) error {
			// In guacone, we ingest directly without NATS
			// no csub here, user-facing single run
			if _, err := ingestor.Ingest(ctx, d, opts.graphqlEndpoint, transport, nil, false, false, false, false); err != nil {
				return fmt.Errorf("unable to ingest document: %v", err)
			}
			totalNum += 1
			return nil
		}

		errHandler := func(err error) bool {
			if err == nil {
				logger.Info("certifier ended gracefully")
				return true
			}
			logger.Errorf("certifier ended with error: %v", err)
			return true
		}

		if err := certify.Certify(ctx, packageQuery, emit, errHandler, opts.poll, opts.interval); err != nil {
			logger.Fatal(err)
		}

		logger.Infof("completed ingesting %v documents", totalNum)
	},
}

func validateDatadogOneFlags(
	graphqlEndpoint,
	headerFile,
	interval,
	certifierLatencyStr string,
	batchSize int, lastScan int,
	poll bool,
) (datadogOneOptions, error) {
	var opts datadogOneOptions
	opts.graphqlEndpoint = graphqlEndpoint
	opts.headerFile = headerFile

	i, err := time.ParseDuration(interval)
	if err != nil {
		return opts, err
	}
	opts.interval = i
	if certifierLatencyStr != "" {
		addedLatency, err := time.ParseDuration(certifierLatencyStr)
		if err != nil {
			return opts, fmt.Errorf("failed to parser duration with error: %w", err)
		}
		opts.addedLatency = &addedLatency
	} else {
		opts.addedLatency = nil
	}

	opts.batchSize = batchSize
	if lastScan != 0 {
		opts.lastScan = &lastScan
	}
	opts.poll = poll
	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{
		"interval",
		"header-file",
		"certifier-latency",
		"certifier-batch-size",
		"last-scan",
		"poll",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	datadogOneCmd.PersistentFlags().AddFlagSet(set)
	if err := viper.BindPFlags(datadogOneCmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}

	// add to certifierCmd of guacone like others
	certifierCmd.AddCommand(datadogOneCmd)
}
