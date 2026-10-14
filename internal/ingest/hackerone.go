package ingest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"target-service/internal/model"
)

// DefaultHackerOneAPI is the HackerOne Hacker API base
// (https://api.hackerone.com/hacker-resources/).
const DefaultHackerOneAPI = "https://api.hackerone.com"

// ponytail: 10 pages x 100 structured scopes = 1000 assets per program, which
// covers any real program. Raise the cap if a program ever lists more.
const hackerOneMaxScopePages = 10

// HackerOneProgramConnector fetches a program's structured scope + policy from
// the HackerOne Hacker API (reuses the Basic-auth request pattern of
// knowledge-service/internal/ingest/hackerone.go). Requires HACKERONE_API_USERNAME
// and HACKERONE_API_TOKEN; without them FetchProgram returns
// ErrPolicySourceUnavailable (no scraping fallback — never fabricate scope).
type HackerOneProgramConnector struct {
	base     string
	username string
	token    string
	client   *http.Client
}

// NewHackerOneProgramConnector builds the connector. base defaults to
// DefaultHackerOneAPI; client defaults to a 30s client.
func NewHackerOneProgramConnector(base, username, token string, client *http.Client) *HackerOneProgramConnector {
	if base == "" {
		base = DefaultHackerOneAPI
	}
	if client == nil {
		client = defaultClient()
	}
	return &HackerOneProgramConnector{base: strings.TrimRight(base, "/"), username: username, token: token, client: client}
}

func (c *HackerOneProgramConnector) Platform() string { return model.ProgramPlatformHackerOne }

type h1Program struct {
	Data struct {
		Attributes struct {
			Handle string `json:"handle"`
			Name   string `json:"name"`
			Policy string `json:"policy"`
		} `json:"attributes"`
	} `json:"data"`
}

type h1StructuredScopes struct {
	Data []struct {
		Attributes struct {
			AssetType             string `json:"asset_type"`
			AssetIdentifier       string `json:"asset_identifier"`
			EligibleForSubmission bool   `json:"eligible_for_submission"`
		} `json:"attributes"`
	} `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

func (c *HackerOneProgramConnector) FetchProgram(ctx context.Context, handle string) (model.ProgramPolicy, error) {
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return model.ProgramPolicy{}, fmt.Errorf("hackerone: empty handle")
	}
	if c.username == "" || c.token == "" {
		return model.ProgramPolicy{}, fmt.Errorf("hackerone: HACKERONE_API_USERNAME and HACKERONE_API_TOKEN required: %w", ErrPolicySourceUnavailable)
	}
	auth := map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(c.username+":"+c.token)),
	}

	var prog h1Program
	progURL := c.base + "/v1/hackers/programs/" + url.PathEscape(handle)
	if err := getJSONAuth(ctx, c.client, progURL, auth, &prog); err != nil {
		return model.ProgramPolicy{}, fmt.Errorf("hackerone: fetch program %q: %w", handle, err)
	}

	policy := model.ProgramPolicy{
		Platform:  model.ProgramPlatformHackerOne,
		Handle:    handle,
		Name:      prog.Data.Attributes.Name,
		PolicyURL: "https://hackerone.com/" + handle,
	}
	// Keep the raw policy text for audit/defensibility.
	policy.RawPolicy, _ = json.Marshal(map[string]string{"policy": prog.Data.Attributes.Policy})

	// Page through the structured scopes.
	scopeURL := c.base + "/v1/hackers/programs/" + url.PathEscape(handle) + "/structured_scopes"
	for page := 1; page <= hackerOneMaxScopePages; page++ {
		q := url.Values{}
		q.Set("page[size]", "100")
		q.Set("page[number]", strconv.Itoa(page))
		var scopes h1StructuredScopes
		if err := getJSONAuth(ctx, c.client, scopeURL+"?"+q.Encode(), auth, &scopes); err != nil {
			return model.ProgramPolicy{}, fmt.Errorf("hackerone: fetch scopes %q page %d: %w", handle, page, err)
		}
		if len(scopes.Data) == 0 {
			break
		}
		for _, s := range scopes.Data {
			id := strings.TrimSpace(s.Attributes.AssetIdentifier)
			if id == "" {
				continue
			}
			policy.Assets = append(policy.Assets, model.ProgramPolicyAsset{
				AssetType:  mapHackerOneAssetType(s.Attributes.AssetType, id),
				Identifier: id,
				InScope:    s.Attributes.EligibleForSubmission,
			})
		}
		if scopes.Links.Next == "" {
			break
		}
	}
	return policy, nil
}

// mapHackerOneAssetType maps a HackerOne asset_type onto our asset_type. A URL
// identifier that begins with "*." is a wildcard regardless of the stated type.
func mapHackerOneAssetType(h1Type, identifier string) string {
	if strings.HasPrefix(identifier, "*.") {
		return model.ProgramAssetTypeWildcard
	}
	switch strings.ToUpper(strings.TrimSpace(h1Type)) {
	case "WILDCARD":
		return model.ProgramAssetTypeWildcard
	case "DOMAIN":
		return model.ProgramAssetTypeDomain
	case "IP_ADDRESS":
		return model.ProgramAssetTypeIP
	case "CIDR":
		return model.ProgramAssetTypeCIDR
	case "URL":
		return model.ProgramAssetTypeURL
	default:
		return model.ProgramAssetTypeOther
	}
}
