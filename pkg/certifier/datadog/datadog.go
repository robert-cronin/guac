////
// Copyright 2022 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package datadog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	ingestor "github.com/guacsec/guac/pkg/assembler/clients/helpers"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/clients"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/version"

	jsoniter "github.com/json-iterator/go"
	"golang.org/x/time/rate"
)

var (
	json              = jsoniter.ConfigCompatibleWithStandardLibrary
	rateLimit         = 10000
	rateLimitInterval = 30 * time.Second
)

const (
	NPM_MANIFEST_URL  string = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/manifest.json"
	PYPI_MANIFEST_URL string = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/pypi/manifest.json"
	VERSION           string = "0.0.1"
	PRODUCER_ID       string = "guacsec/guac"
	DataDogCollector  string = "datadog_certifier"
)

var ErrDataDogComponentTypeMismatch error = errors.New("rootComponent type is not []*root_package.PackageNode")

type MaliciousPackages map[string][]string

type datadogCertifier struct {
	httpClient    *http.Client
	npmData       MaliciousPackages
	pypiData      MaliciousPackages
	assemblerFunc assemblerFuncType
}

type assemblerFuncType func([]assembler.IngestPredicates) (*ingestor.AssemblerIngestedIDs, error)

type CertifierOption func(*datadogCertifier)

// WithHTTPClient allows overriding the default HTTP client
func WithHTTPClient(client *http.Client) CertifierOption {
	return func(d *datadogCertifier) {
		d.httpClient = client
	}
}

// NewDataDogCertificationParser initializes the DataDog Certifier
func NewDataDogCertificationParser(ctx context.Context, assemblerFunc assemblerFuncType, opts ...CertifierOption) (certifier.Certifier, error) {
	limiter := rate.NewLimiter(rate.Every(rateLimitInterval), rateLimit)
	transport := clients.NewRateLimitedTransport(version.UATransport, limiter)
	defaultClient := &http.Client{Transport: transport}

	d := &datadogCertifier{
		httpClient:    defaultClient,
		assemblerFunc: assemblerFunc,
	}

	// Apply options
	for _, opt := range opts {
		opt(d)
	}

	if err := d.fetchManifests(); err != nil {
		return nil, fmt.Errorf("failed to fetch DataDog manifests: %w", err)
	}

	return d, nil
}

func (d *datadogCertifier) fetchManifests() error {
	npmResp, err := d.httpClient.Get(NPM_MANIFEST_URL)
	if err != nil {
		return fmt.Errorf("failed to fetch NPM manifest: %w", err)
	}
	defer npmResp.Body.Close()

	if err := json.NewDecoder(npmResp.Body).Decode(&d.npmData); err != nil {
		return fmt.Errorf("failed to decode NPM manifest: %w", err)
	}

	pypiResp, err := d.httpClient.Get(PYPI_MANIFEST_URL)
	if err != nil {
		return fmt.Errorf("failed to fetch PyPI manifest: %w", err)
	}
	defer pypiResp.Body.Close()

	if err := json.NewDecoder(pypiResp.Body).Decode(&d.pypiData); err != nil {
		return fmt.Errorf("failed to decode PyPI manifest: %w", err)
	}

	return nil
}

func (d *datadogCertifier) CertifyComponent(ctx context.Context, rootComponent interface{}, _ chan<- *processor.Document) error {
	packageNodes, ok := rootComponent.([]*root_package.PackageNode)
	if !ok {
		return ErrDataDogComponentTypeMismatch
	}

	predicates := &assembler.IngestPredicates{}
	currentTime := time.Now().UTC()

	for _, node := range packageNodes {
		purl := node.

		// Skip packages that aren't npm or pypi
		if !strings.HasPrefix(purl, "pkg:npm/") && !strings.HasPrefix(purl, "pkg:pypi/") {
			continue
		}

		pkgInput, err := helpers.PurlToPkg(purl)
		if err != nil {
			return fmt.Errorf("failed to parse PURL %s: %w", purl, err)
		}

		var versions []string
		if strings.HasPrefix(purl, "pkg:npm/") {
			fullName := pkgInput.Name
			if pkgInput.Namespace != nil && *pkgInput.Namespace != "" {
				// Create the package name in npm format, handling URL encoding
				namespace := strings.TrimPrefix(*pkgInput.Namespace, "@")
				if strings.HasPrefix(*pkgInput.Namespace, "%40") {
					namespace = strings.TrimPrefix(*pkgInput.Namespace, "%40")
				}
				fullName = "@" + namespace + "/" + pkgInput.Name
			}
			versions = d.npmData[fullName]
		} else {
			versions = d.pypiData[pkgInput.Name]
		}

		if len(versions) == 0 {
			continue
		}

		certifyBad := &assembler.CertifyBadIngest{
			Pkg:          pkgInput,
			PkgMatchFlag: generated.MatchFlags{Pkg: generated.PkgMatchTypeAllVersions},
			CertifyBad: &generated.CertifyBadInputSpec{
				Justification: fmt.Sprintf("Package found in DataDog's malicious software packages dataset. Affected versions: %v", versions),
				Origin:        "DataDog Malicious Software Packages Dataset",
				Collector:     DataDogCollector,
				KnownSince:    currentTime,
			},
		}

		predicates.CertifyBad = append(predicates.CertifyBad, *certifyBad)
	}

	if len(predicates.CertifyBad) > 0 {
		if _, err := d.assemblerFunc([]assembler.IngestPredicates{*predicates}); err != nil {
			return fmt.Errorf("unable to assemble graphs: %w", err)
		}
	}

	return nil
}
