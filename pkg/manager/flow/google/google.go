//SPDX-License-Identifier: Apache-2.0

package google

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/google/uuid"
	"github.com/grokify/go-pkce"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/internal/db/generated"
	"github.com/loopholelabs/auth/internal/db/pgxtypes"
	"github.com/loopholelabs/auth/pkg/manager/flow"
)

var (
	ErrInvalidOptions   = errors.New("invalid options")
	ErrDBIsRequired     = errors.New("db is required")
	ErrCreatingFlow     = errors.New("error creating flow")
	ErrCompletingFlow   = errors.New("error completing flow")
	ErrInvalidNextURL   = errors.New("invalid next URL")
	ErrInvalidResponse  = errors.New("invalid response")
	ErrNoVerifiedEmails = errors.New("no verified emails")
)

var (
	now = time.Now
)

const (
	GCInterval = time.Minute
	Expiry     = time.Minute * 5
	Timeout    = time.Second * 30
)

var (
	defaultScopes = []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"}
)

type user struct {
	ID       int64  `json:"sub"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Verified bool   `json:"email_verified"`
}

type Options struct {
	RedirectURL  string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client // Optional: custom HTTP client for testing
}

type Google struct {
	logger     types.Logger
	db         *db.DB
	config     *oauth2.Config
	httpClient *http.Client

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

func New(options Options, db *db.DB, logger types.Logger) (*Google, error) {
	if options.RedirectURL == "" || options.ClientID == "" || options.ClientSecret == "" {
		return nil, ErrInvalidOptions
	}

	if db == nil {
		return nil, ErrDBIsRequired
	}

	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	ctx, cancel := context.WithCancel(context.Background())
	g := &Google{
		logger:     logger.SubLogger("GOOGLE"),
		db:         db,
		httpClient: httpClient,
		config: &oauth2.Config{
			ClientID:     options.ClientID,
			ClientSecret: options.ClientSecret,
			Endpoint:     google.Endpoint,
			RedirectURL:  options.RedirectURL,
			Scopes:       defaultScopes,
		},
		ctx:    ctx,
		cancel: cancel,
	}

	g.wg.Add(1)
	go g.doGC()

	return g, nil
}

func (c *Google) Close() error {
	c.cancel()
	c.wg.Wait()
	return nil
}

func (c *Google) CreateFlow(ctx context.Context, deviceIdentifier string, userIdentifier string, nextURL string) (string, error) {
	if nextURL == "" {
		return "", errors.Join(ErrCreatingFlow, ErrInvalidNextURL)
	}
	verifier, err := pkce.NewCodeVerifier(-1)
	if err != nil {
		return "", errors.Join(ErrCreatingFlow, err)
	}

	identifierStr := uuid.New().String()
	var deviceID, userID pgtype.UUID
	if deviceIdentifier != "" {
		deviceID = pgxtypes.UUIDFromString(deviceIdentifier)
	} else {
		deviceID = pgtype.UUID{Valid: false}
	}
	if userIdentifier != "" {
		userID = pgxtypes.UUIDFromString(userIdentifier)
	} else {
		userID = pgtype.UUID{Valid: false}
	}

	params := generated.CreateGoogleOAuthFlowParams{
		Identifier:       pgxtypes.UUIDFromString(identifierStr),
		Verifier:         verifier,
		Challenge:        pkce.CodeChallengeS256(verifier),
		DeviceIdentifier: deviceID,
		UserIdentifier:   userID,
		NextUrl:          nextURL,
	}

	c.logger.Debug().Msg("creating flow")
	err = c.db.Queries.CreateGoogleOAuthFlow(ctx, params)
	if err != nil {
		return "", errors.Join(ErrCreatingFlow, err)
	}

	return c.config.AuthCodeURL(identifierStr, oauth2.AccessTypeOnline, oauth2.SetAuthURLParam(pkce.ParamCodeChallenge, params.Challenge), oauth2.SetAuthURLParam(pkce.ParamCodeChallengeMethod, pkce.MethodS256)), nil
}

func (c *Google) CompleteFlow(ctx context.Context, identifier string, code string) (flow.Data, error) {
	c.logger.Debug().Str("identifier", identifier).Msg("completing flow")
	tx, err := c.db.BeginTx(ctx, sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, err)
	}

	defer func() {
		err := tx.Rollback(ctx)
		if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			c.logger.Error().Err(err).Msg("failed to rollback transaction")
		}
	}()

	qtx := c.db.Queries.WithTx(tx)

	f, err := qtx.GetGoogleOAuthFlowByIdentifier(ctx, pgxtypes.UUIDFromString(identifier))
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, err)
	}

	num, err := qtx.DeleteGoogleOAuthFlowByIdentifier(ctx, pgxtypes.UUIDFromString(identifier))
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, err)
	}
	if num == 0 {
		return flow.Data{}, errors.Join(ErrCompletingFlow, sql.ErrNoRows)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, err)
	}

	// Use context with custom HTTP client for OAuth2 token exchange
	oauth2Ctx := ctx
	if c.httpClient != nil {
		oauth2Ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
	}

	token, err := c.config.Exchange(oauth2Ctx, code, oauth2.SetAuthURLParam(pkce.ParamCodeVerifier, f.Verifier))
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, err)
	}

	// Get User Info

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", token.AccessToken))

	res, err := c.httpClient.Do(req)
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, err)
	}

	if res.StatusCode != http.StatusOK {
		return flow.Data{}, errors.Join(ErrCompletingFlow, ErrInvalidResponse)
	}

	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, err)
	}

	var u user
	err = json.Unmarshal(body, &u)
	if err != nil {
		return flow.Data{}, errors.Join(ErrCompletingFlow, err)
	}

	deviceIdentifier, _ := pgxtypes.StringFromUUID(f.DeviceIdentifier) // OK if empty
	userIdentifier, _ := pgxtypes.StringFromUUID(f.UserIdentifier)     // OK if empty

	data := flow.Data{
		ProviderIdentifier: strconv.FormatInt(u.ID, 10),
		UserName:           u.Name,
		NextURL:            f.NextUrl,
		DeviceIdentifier:   deviceIdentifier,
		UserIdentifier:     userIdentifier,
	}

	if !u.Verified || u.Email == "" {
		return flow.Data{}, errors.Join(ErrCompletingFlow, ErrNoVerifiedEmails)
	}

	data.PrimaryEmail = u.Email
	data.VerifiedEmails = append(data.VerifiedEmails, u.Email)

	return data, nil
}

func (c *Google) gc() (int64, error) {
	ctx, cancel := context.WithTimeout(c.ctx, Timeout)
	defer cancel()
	return c.db.Queries.DeleteGoogleOAuthFlowsBeforeCreatedAt(ctx, pgxtypes.TimestampFromTime(now().Add(-Expiry)))
}

func (c *Google) doGC() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			c.logger.Debug().Msg("GC stopped")
			return
		case <-time.After(GCInterval):
			deleted, err := c.gc()
			if err != nil {
				c.logger.Error().Err(err).Msg("failed to garbage collect expired flows")
			} else {
				c.logger.Debug().Msgf("garbage collected %d expired flows", deleted)
			}
		}
	}
}
