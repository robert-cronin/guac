// Copyright 2024 The GUAC Authors.
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

package eol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/clients"
	"github.com/guacsec/guac/pkg/handler/processor"
	"golang.org/x/time/rate"
)

var (
	eolAPIBase = "https://endoflife.date/api"
)

const (
	EOLCollector   = "endoflife.date"
	rateLimit      = 10
	rateLimitBurst = 1
)

type eolCertifier struct {
	client *http.Client
}

type CycleData struct {
	Cycle             string `json:"cycle"`
	ReleaseDate       string `json:"releaseDate"`
	EOL               string `json:"eol"`
	Latest            string `json:"latest"`
	LatestReleaseDate string `json:"latestReleaseDate"`
	LTS               bool   `json:"lts"`
}

func NewEOLCertifier() certifier.Certifier {
	limiter := rate.NewLimiter(rate.Every(time.Second/time.Duration(rateLimit)), rateLimitBurst)
	client := &http.Client{
		Transport: clients.NewRateLimitedTransport(http.DefaultTransport, limiter),
	}
	return &eolCertifier{client: client}
}

func (e *eolCertifier) CertifyComponent(ctx context.Context, rootComponent interface{}, docChannel chan<- *processor.Document) error {
	packageNodes, ok := rootComponent.([]*root_package.PackageNode)
	if !ok {
		return fmt.Errorf("rootComponent type is not []*root_package.PackageNode")
	}

	products, err := e.fetchAllProducts()
	if err != nil {
		return fmt.Errorf("failed to fetch products: %w", err)
	}

	for _, node := range packageNodes {
		if product, ok := findMatchingProduct(node.Purl, products); ok {
			eolData, err := e.fetchProductEOL(product)
			if err != nil {
				return fmt.Errorf("failed to fetch EOL data for %s: %w", product, err)
			}

			if err := e.generateMetadata(ctx, node, product, eolData, docChannel); err != nil {
				return fmt.Errorf("failed to generate metadata for %s: %w", node.Purl, err)
			}
		}
	}

	return nil
}

func (e *eolCertifier) fetchAllProducts() ([]string, error) {
	resp, err := e.client.Get(fmt.Sprintf("%s/all.json", eolAPIBase))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var products []string
	if err := json.NewDecoder(resp.Body).Decode(&products); err != nil {
		return nil, err
	}

	return products, nil
}

func (e *eolCertifier) fetchProductEOL(product string) ([]CycleData, error) {
	resp, err := e.client.Get(fmt.Sprintf("%s/%s.json", eolAPIBase, product))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var eolData []CycleData
	if err := json.NewDecoder(resp.Body).Decode(&eolData); err != nil {
		return nil, err
	}

	return eolData, nil
}

func (e *eolCertifier) generateMetadata(ctx context.Context, node *root_package.PackageNode, product string, eolData []CycleData, docChannel chan<- *processor.Document) error {
	version := extractVersion(node.Purl)

	var relevantCycle *CycleData
	for i, cycleData := range eolData {
		if cycleData.Cycle == version {
			relevantCycle = &eolData[i]
			break
		}
	}

	if relevantCycle == nil && len(eolData) > 0 {
		// If no matching cycle is found, use the latest (first in the list)
		relevantCycle = &eolData[0]
	}

	if relevantCycle == nil {
		return fmt.Errorf("no relevant cycle data found for %s", node.Purl)
	}

	// serialize the cycle data
	cycleDataBytes, err := json.Marshal(relevantCycle)
	if err != nil {
		return fmt.Errorf("failed to serialize cycle data: %w", err)
	}

	doc := &processor.Document{
		Blob:   cycleDataBytes,
		Type:   processor.DocumentEOL,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector:   EOLCollector,
			Source:      EOLCollector,
			DocumentRef: fmt.Sprintf("%s/%s.json", eolAPIBase, product),
		},
	}
	docChannel <- doc

	return nil
}

func findMatchingProduct(purl string, products []string) (string, bool) {
	parts := strings.Split(purl, "/")
	if len(parts) < 2 {
		return "", false
	}

	packageName := strings.Split(parts[1], "@")[0]
	packageName = strings.ToLower(packageName)

	for _, product := range products {
		if strings.Contains(packageName, product) || strings.Contains(product, packageName) {
			return product, true
		}
	}

	return "", false
}

func extractVersion(purl string) string {
	p, err := helpers.PurlToPkg(purl)
	if err != nil {
		return ""
	}
	if p.Version == nil || *p.Version == "" {
		return ""
	}

	return *p.Version
}
