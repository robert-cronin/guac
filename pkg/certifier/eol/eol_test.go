//
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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEOLCertifier(t *testing.T) {
	certifier := NewEOLCertifier()
	assert.NotNil(t, certifier, "NewEOLCertifier should return a non-nil certifier")
	_, ok := certifier.(*eolCertifier)
	assert.True(t, ok, "NewEOLCertifier should return an instance of eolCertifier")
}

func TestCertifyComponent(t *testing.T) {
	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/all.json":
			json.NewEncoder(w).Encode([]string{"sapmachine", "argo-cd"})
		case "/api/sapmachine.json":
			json.NewEncoder(w).Encode([]CycleData{
				{
					Cycle:             "21",
					ReleaseDate:       "2023-09-18",
					EOL:               "2028-09-01",
					Latest:            "21.0.5",
					LatestReleaseDate: "2024-10-15",
					LTS:               true,
				},
				{
					Cycle:             "20",
					ReleaseDate:       "2023-03-17",
					EOL:               "2023-09-19",
					Latest:            "20.0.2",
					LatestReleaseDate: "2023-07-18",
					LTS:               false,
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	eolAPIBase = server.URL + "/api"

	// Create a test certifier with the mock server
	certifier := &eolCertifier{
		client: server.Client(),
	}

	// Test input
	rootComponent := []*root_package.PackageNode{
		{Purl: "pkg:maven/com.sap.sapmachine/sapmachine@21.0.5"}, // exists in the eol data
		{Purl: "pkg:npm/unknown@2.0.0"},                          // does not exist in the eol data
	}

	// Channel to receive documents
	docChan := make(chan *processor.Document, 10)

	// Run the certifier
	err := certifier.CertifyComponent(context.Background(), rootComponent, docChan)
	require.NoError(t, err)

	// Check the results
	close(docChan)
	docs := make([]*processor.Document, 0)
	for doc := range docChan {
		docs = append(docs, doc)
	}

	assert.Len(t, docs, 1, "Expected 1 document to be generated")
	singleDoc := docs[0]

	// Check the blob content
	actualBlob := string(singleDoc.Blob)
	assert.Contains(t, actualBlob, "21.0.5", "Document should contain the correct version")
	assert.Contains(t, actualBlob, "2028-09-01", "Document should contain the EOL date")
	assert.Contains(t, actualBlob, "\"lts\":true", "Document should indicate LTS status")

	// Check the document metadata
	assert.Equal(t, processor.DocumentEOL, singleDoc.Type, "Document type should be EOL")
	assert.Equal(t, processor.FormatJSON, singleDoc.Format, "Document format should be JSON")
	assert.Equal(t, EOLCollector, singleDoc.SourceInformation.Collector, "Collector should be endoflife.date")
	assert.Equal(t, EOLCollector, singleDoc.SourceInformation.Source, "Source should be endoflife.date")
	assert.Contains(t, singleDoc.SourceInformation.DocumentRef, "sapmachine.json", "DocumentRef should contain sapmachine.json")
}

func TestFetchAllProducts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]string{"sapmachine", "nodejs"})
	}))
	defer server.Close()
	eolAPIBase = server.URL + "/api"

	certifier := &eolCertifier{
		client: server.Client(),
	}

	products, err := certifier.fetchAllProducts()
	require.NoError(t, err)
	assert.Equal(t, []string{"sapmachine", "nodejs"}, products)
}

func TestFetchProductEOL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]CycleData{
			{
				Cycle:             "21",
				ReleaseDate:       "2023-09-18",
				EOL:               "2028-09-01",
				Latest:            "21.0.5",
				LatestReleaseDate: "2024-10-15",
				LTS:               true,
			},
		})
	}))
	defer server.Close()
	eolAPIBase = server.URL + "/api"

	certifier := &eolCertifier{
		client: server.Client(),
	}

	eolData, err := certifier.fetchProductEOL("sapmachine")
	require.NoError(t, err)
	assert.Len(t, eolData, 1)
	assert.Equal(t, "21", eolData[0].Cycle)
	assert.Equal(t, "2028-09-01", eolData[0].EOL)
	assert.True(t, eolData[0].LTS)
}

func TestGenerateMetadata(t *testing.T) {
	certifier := &eolCertifier{}
	node := &root_package.PackageNode{Purl: "pkg:maven/com.sap.sapmachine/sapmachine@21.0.5"}
	eolData := []CycleData{
		{
			Cycle:             "21",
			ReleaseDate:       "2023-09-18",
			EOL:               "2028-09-01",
			Latest:            "21.0.5",
			LatestReleaseDate: "2024-10-15",
			LTS:               true,
		},
	}
	docChan := make(chan *processor.Document, 1)

	err := certifier.generateMetadata(context.Background(), node, "sapmachine", eolData, docChan)
	require.NoError(t, err)

	close(docChan)
	docs := make([]*processor.Document, 0)
	for doc := range docChan {
		docs = append(docs, doc)
	}

	assert.Len(t, docs, 1, "Expected 1 document to be generated")

	singleDoc := docs[0]

	// Check the blob content
	actualBlob := string(singleDoc.Blob)
	assert.Contains(t, actualBlob, "21.0.5", "Document should contain the correct version")
	assert.Contains(t, actualBlob, "2028-09-01", "Document should contain the EOL date")
	assert.Contains(t, actualBlob, "\"lts\":true", "Document should indicate LTS status")

	// Check the document metadata
	assert.Equal(t, processor.DocumentEOL, singleDoc.Type, "Document type should be EOL")
	assert.Equal(t, processor.FormatJSON, singleDoc.Format, "Document format should be JSON")
	assert.Equal(t, EOLCollector, singleDoc.SourceInformation.Collector, "Collector should be endoflife.date")
	assert.Equal(t, EOLCollector, singleDoc.SourceInformation.Source, "Source should be endoflife.date")
	assert.Contains(t, singleDoc.SourceInformation.DocumentRef, "sapmachine.json", "DocumentRef should contain sapmachine.json")
}
