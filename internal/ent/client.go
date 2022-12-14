/*
	Copyright 2023 Loophole Labs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/loopholelabs/auth/internal/ent/migrate"

	"github.com/loopholelabs/auth/internal/ent/deviceflow"
	"github.com/loopholelabs/auth/internal/ent/githubflow"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
)

// Client is the client that holds all ent builders.
type Client struct {
	config
	// Schema is the client for creating, migrating and dropping schema.
	Schema *migrate.Schema
	// DeviceFlow is the client for interacting with the DeviceFlow builders.
	DeviceFlow *DeviceFlowClient
	// GithubFlow is the client for interacting with the GithubFlow builders.
	GithubFlow *GithubFlowClient
}

// NewClient creates a new client configured with the given options.
func NewClient(opts ...Option) *Client {
	cfg := config{log: log.Println, hooks: &hooks{}}
	cfg.options(opts...)
	client := &Client{config: cfg}
	client.init()
	return client
}

func (c *Client) init() {
	c.Schema = migrate.NewSchema(c.driver)
	c.DeviceFlow = NewDeviceFlowClient(c.config)
	c.GithubFlow = NewGithubFlowClient(c.config)
}

// Open opens a database/sql.DB specified by the driver name and
// the data source name, and returns a new client attached to it.
// Optional parameters can be added for configuring the client.
func Open(driverName, dataSourceName string, options ...Option) (*Client, error) {
	switch driverName {
	case dialect.MySQL, dialect.Postgres, dialect.SQLite:
		drv, err := sql.Open(driverName, dataSourceName)
		if err != nil {
			return nil, err
		}
		return NewClient(append(options, Driver(drv))...), nil
	default:
		return nil, fmt.Errorf("unsupported driver: %q", driverName)
	}
}

// Tx returns a new transactional client. The provided context
// is used until the transaction is committed or rolled back.
func (c *Client) Tx(ctx context.Context) (*Tx, error) {
	if _, ok := c.driver.(*txDriver); ok {
		return nil, errors.New("ent: cannot start a transaction within a transaction")
	}
	tx, err := newTx(ctx, c.driver)
	if err != nil {
		return nil, fmt.Errorf("ent: starting a transaction: %w", err)
	}
	cfg := c.config
	cfg.driver = tx
	return &Tx{
		ctx:        ctx,
		config:     cfg,
		DeviceFlow: NewDeviceFlowClient(cfg),
		GithubFlow: NewGithubFlowClient(cfg),
	}, nil
}

// BeginTx returns a transactional client with specified options.
func (c *Client) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	if _, ok := c.driver.(*txDriver); ok {
		return nil, errors.New("ent: cannot start a transaction within a transaction")
	}
	tx, err := c.driver.(interface {
		BeginTx(context.Context, *sql.TxOptions) (dialect.Tx, error)
	}).BeginTx(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("ent: starting a transaction: %w", err)
	}
	cfg := c.config
	cfg.driver = &txDriver{tx: tx, drv: c.driver}
	return &Tx{
		ctx:        ctx,
		config:     cfg,
		DeviceFlow: NewDeviceFlowClient(cfg),
		GithubFlow: NewGithubFlowClient(cfg),
	}, nil
}

// Debug returns a new debug-client. It's used to get verbose logging on specific operations.
//
//	client.Debug().
//		DeviceFlow.
//		Query().
//		Count(ctx)
func (c *Client) Debug() *Client {
	if c.debug {
		return c
	}
	cfg := c.config
	cfg.driver = dialect.Debug(c.driver, c.log)
	client := &Client{config: cfg}
	client.init()
	return client
}

// Close closes the database connection and prevents new queries from starting.
func (c *Client) Close() error {
	return c.driver.Close()
}

// Use adds the mutation hooks to all the entity clients.
// In order to add hooks to a specific client, call: `client.Node.Use(...)`.
func (c *Client) Use(hooks ...Hook) {
	c.DeviceFlow.Use(hooks...)
	c.GithubFlow.Use(hooks...)
}

// DeviceFlowClient is a client for the DeviceFlow schema.
type DeviceFlowClient struct {
	config
}

// NewDeviceFlowClient returns a client for the DeviceFlow from the given config.
func NewDeviceFlowClient(c config) *DeviceFlowClient {
	return &DeviceFlowClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `deviceflow.Hooks(f(g(h())))`.
func (c *DeviceFlowClient) Use(hooks ...Hook) {
	c.hooks.DeviceFlow = append(c.hooks.DeviceFlow, hooks...)
}

// Create returns a builder for creating a DeviceFlow entity.
func (c *DeviceFlowClient) Create() *DeviceFlowCreate {
	mutation := newDeviceFlowMutation(c.config, OpCreate)
	return &DeviceFlowCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of DeviceFlow entities.
func (c *DeviceFlowClient) CreateBulk(builders ...*DeviceFlowCreate) *DeviceFlowCreateBulk {
	return &DeviceFlowCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for DeviceFlow.
func (c *DeviceFlowClient) Update() *DeviceFlowUpdate {
	mutation := newDeviceFlowMutation(c.config, OpUpdate)
	return &DeviceFlowUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *DeviceFlowClient) UpdateOne(df *DeviceFlow) *DeviceFlowUpdateOne {
	mutation := newDeviceFlowMutation(c.config, OpUpdateOne, withDeviceFlow(df))
	return &DeviceFlowUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *DeviceFlowClient) UpdateOneID(id int) *DeviceFlowUpdateOne {
	mutation := newDeviceFlowMutation(c.config, OpUpdateOne, withDeviceFlowID(id))
	return &DeviceFlowUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for DeviceFlow.
func (c *DeviceFlowClient) Delete() *DeviceFlowDelete {
	mutation := newDeviceFlowMutation(c.config, OpDelete)
	return &DeviceFlowDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *DeviceFlowClient) DeleteOne(df *DeviceFlow) *DeviceFlowDeleteOne {
	return c.DeleteOneID(df.ID)
}

// DeleteOneID returns a builder for deleting the given entity by its id.
func (c *DeviceFlowClient) DeleteOneID(id int) *DeviceFlowDeleteOne {
	builder := c.Delete().Where(deviceflow.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &DeviceFlowDeleteOne{builder}
}

// Query returns a query builder for DeviceFlow.
func (c *DeviceFlowClient) Query() *DeviceFlowQuery {
	return &DeviceFlowQuery{
		config: c.config,
	}
}

// Get returns a DeviceFlow entity by its id.
func (c *DeviceFlowClient) Get(ctx context.Context, id int) (*DeviceFlow, error) {
	return c.Query().Where(deviceflow.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *DeviceFlowClient) GetX(ctx context.Context, id int) *DeviceFlow {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// Hooks returns the client hooks.
func (c *DeviceFlowClient) Hooks() []Hook {
	return c.hooks.DeviceFlow
}

// GithubFlowClient is a client for the GithubFlow schema.
type GithubFlowClient struct {
	config
}

// NewGithubFlowClient returns a client for the GithubFlow from the given config.
func NewGithubFlowClient(c config) *GithubFlowClient {
	return &GithubFlowClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `githubflow.Hooks(f(g(h())))`.
func (c *GithubFlowClient) Use(hooks ...Hook) {
	c.hooks.GithubFlow = append(c.hooks.GithubFlow, hooks...)
}

// Create returns a builder for creating a GithubFlow entity.
func (c *GithubFlowClient) Create() *GithubFlowCreate {
	mutation := newGithubFlowMutation(c.config, OpCreate)
	return &GithubFlowCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of GithubFlow entities.
func (c *GithubFlowClient) CreateBulk(builders ...*GithubFlowCreate) *GithubFlowCreateBulk {
	return &GithubFlowCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for GithubFlow.
func (c *GithubFlowClient) Update() *GithubFlowUpdate {
	mutation := newGithubFlowMutation(c.config, OpUpdate)
	return &GithubFlowUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *GithubFlowClient) UpdateOne(gf *GithubFlow) *GithubFlowUpdateOne {
	mutation := newGithubFlowMutation(c.config, OpUpdateOne, withGithubFlow(gf))
	return &GithubFlowUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *GithubFlowClient) UpdateOneID(id int) *GithubFlowUpdateOne {
	mutation := newGithubFlowMutation(c.config, OpUpdateOne, withGithubFlowID(id))
	return &GithubFlowUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for GithubFlow.
func (c *GithubFlowClient) Delete() *GithubFlowDelete {
	mutation := newGithubFlowMutation(c.config, OpDelete)
	return &GithubFlowDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *GithubFlowClient) DeleteOne(gf *GithubFlow) *GithubFlowDeleteOne {
	return c.DeleteOneID(gf.ID)
}

// DeleteOneID returns a builder for deleting the given entity by its id.
func (c *GithubFlowClient) DeleteOneID(id int) *GithubFlowDeleteOne {
	builder := c.Delete().Where(githubflow.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &GithubFlowDeleteOne{builder}
}

// Query returns a query builder for GithubFlow.
func (c *GithubFlowClient) Query() *GithubFlowQuery {
	return &GithubFlowQuery{
		config: c.config,
	}
}

// Get returns a GithubFlow entity by its id.
func (c *GithubFlowClient) Get(ctx context.Context, id int) (*GithubFlow, error) {
	return c.Query().Where(githubflow.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *GithubFlowClient) GetX(ctx context.Context, id int) *GithubFlow {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// Hooks returns the client hooks.
func (c *GithubFlowClient) Hooks() []Hook {
	return c.hooks.GithubFlow
}
