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
	"fmt"

	jsoniter "github.com/json-iterator/go"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	justification = "Retrieved from endoflife.date"
)

type parser struct {
	pkg              *generated.PkgInputSpec
	collectedEOLInfo []assembler.HasMetadataIngest
}

// NewEOLCertificationParser initializes the parser
func NewEOLCertificationParser() common.DocumentParser {
	return &parser{}
}

// initializeEOLParser clears out all values for the next iteration
func (e *parser) initializeEOLParser() {
	e.pkg = nil
	e.collectedEOLInfo = make([]assembler.HasMetadataIngest, 0)
}

// Parse breaks out the document into the graph components
func (e *parser) Parse(ctx context.Context, doc *processor.Document) error {
	e.initializeEOLParser()
	statement, err := parseEOLCertifyPredicate(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse EOL predicate: %w", err)
	}
	if err := e.parseSubject(statement); err != nil {
		return fmt.Errorf("unable to parse subject of statement: %w", err)
	}
	if err := e.parseEOL(ctx, statement); err != nil {
		return fmt.Errorf("unable to parse EOL statement: %w", err)
	}
	return nil
}

func parseEOLCertifyPredicate(p []byte) (*attestation.EOLStatement, error) {
	predicate := attestation.EOLStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}

func (e *parser) parseSubject(s *attestation.EOLStatement) error {
	for _, sub := range s.Statement.Subject {
		p, err := helpers.PurlToPkg(sub.Uri)
		if err != nil {
			return fmt.Errorf("failed to parse uri: %s to a package with error: %w", sub.Uri, err)
		}
		e.pkg = p
	}
	return nil
}

// parseEOL parses the attestation to collect the EOL information
func (e *parser) parseEOL(_ context.Context, s *attestation.EOLStatement) error {
	if e.pkg == nil {
		return fmt.Errorf("package not specified for EOL information")
	}

	eolInfo := assembler.HasMetadataIngest{
		Pkg:          e.pkg,
		PkgMatchFlag: generated.MatchFlags{Pkg: generated.PkgMatchTypeSpecificVersion},
		HasMetadata: &generated.HasMetadataInputSpec{
			Key: "endoflife",
			Value: fmt.Sprintf("product:%s,cycle:%s,version:%s,isEOL:%v,eolDate:%s,lts:%v,latest:%s",
				s.Predicate.Product, s.Predicate.Cycle, s.Predicate.Version, s.Predicate.IsEOL, s.Predicate.EOLDate, s.Predicate.LTS, s.Predicate.Latest),
			Timestamp:     s.Predicate.Metadata.ScannedOn.UTC(),
			Justification: justification,
		},
	}

	e.collectedEOLInfo = append(e.collectedEOLInfo, eolInfo)

	return nil
}

func (e *parser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	return &assembler.IngestPredicates{
		HasMetadata: e.collectedEOLInfo,
	}
}

// GetIdentities gets the identity node from the document if they exist
func (e *parser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (e *parser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return nil, fmt.Errorf("not yet implemented")
}
