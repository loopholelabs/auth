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
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/loopholelabs/auth/ent/deviceflow"
	"github.com/loopholelabs/auth/ent/predicate"
)

// DeviceFlowQuery is the builder for querying DeviceFlow entities.
type DeviceFlowQuery struct {
	config
	limit      *int
	offset     *int
	unique     *bool
	order      []OrderFunc
	fields     []string
	predicates []predicate.DeviceFlow
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the DeviceFlowQuery builder.
func (dfq *DeviceFlowQuery) Where(ps ...predicate.DeviceFlow) *DeviceFlowQuery {
	dfq.predicates = append(dfq.predicates, ps...)
	return dfq
}

// Limit adds a limit step to the query.
func (dfq *DeviceFlowQuery) Limit(limit int) *DeviceFlowQuery {
	dfq.limit = &limit
	return dfq
}

// Offset adds an offset step to the query.
func (dfq *DeviceFlowQuery) Offset(offset int) *DeviceFlowQuery {
	dfq.offset = &offset
	return dfq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (dfq *DeviceFlowQuery) Unique(unique bool) *DeviceFlowQuery {
	dfq.unique = &unique
	return dfq
}

// Order adds an order step to the query.
func (dfq *DeviceFlowQuery) Order(o ...OrderFunc) *DeviceFlowQuery {
	dfq.order = append(dfq.order, o...)
	return dfq
}

// First returns the first DeviceFlow entity from the query.
// Returns a *NotFoundError when no DeviceFlow was found.
func (dfq *DeviceFlowQuery) First(ctx context.Context) (*DeviceFlow, error) {
	nodes, err := dfq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{deviceflow.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (dfq *DeviceFlowQuery) FirstX(ctx context.Context) *DeviceFlow {
	node, err := dfq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first DeviceFlow ID from the query.
// Returns a *NotFoundError when no DeviceFlow ID was found.
func (dfq *DeviceFlowQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = dfq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{deviceflow.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (dfq *DeviceFlowQuery) FirstIDX(ctx context.Context) int {
	id, err := dfq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single DeviceFlow entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one DeviceFlow entity is found.
// Returns a *NotFoundError when no DeviceFlow entities are found.
func (dfq *DeviceFlowQuery) Only(ctx context.Context) (*DeviceFlow, error) {
	nodes, err := dfq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{deviceflow.Label}
	default:
		return nil, &NotSingularError{deviceflow.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (dfq *DeviceFlowQuery) OnlyX(ctx context.Context) *DeviceFlow {
	node, err := dfq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only DeviceFlow ID in the query.
// Returns a *NotSingularError when more than one DeviceFlow ID is found.
// Returns a *NotFoundError when no entities are found.
func (dfq *DeviceFlowQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = dfq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{deviceflow.Label}
	default:
		err = &NotSingularError{deviceflow.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (dfq *DeviceFlowQuery) OnlyIDX(ctx context.Context) int {
	id, err := dfq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of DeviceFlows.
func (dfq *DeviceFlowQuery) All(ctx context.Context) ([]*DeviceFlow, error) {
	if err := dfq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return dfq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (dfq *DeviceFlowQuery) AllX(ctx context.Context) []*DeviceFlow {
	nodes, err := dfq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of DeviceFlow IDs.
func (dfq *DeviceFlowQuery) IDs(ctx context.Context) ([]int, error) {
	var ids []int
	if err := dfq.Select(deviceflow.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (dfq *DeviceFlowQuery) IDsX(ctx context.Context) []int {
	ids, err := dfq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (dfq *DeviceFlowQuery) Count(ctx context.Context) (int, error) {
	if err := dfq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return dfq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (dfq *DeviceFlowQuery) CountX(ctx context.Context) int {
	count, err := dfq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (dfq *DeviceFlowQuery) Exist(ctx context.Context) (bool, error) {
	if err := dfq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return dfq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (dfq *DeviceFlowQuery) ExistX(ctx context.Context) bool {
	exist, err := dfq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the DeviceFlowQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (dfq *DeviceFlowQuery) Clone() *DeviceFlowQuery {
	if dfq == nil {
		return nil
	}
	return &DeviceFlowQuery{
		config:     dfq.config,
		limit:      dfq.limit,
		offset:     dfq.offset,
		order:      append([]OrderFunc{}, dfq.order...),
		predicates: append([]predicate.DeviceFlow{}, dfq.predicates...),
		// clone intermediate query.
		sql:    dfq.sql.Clone(),
		path:   dfq.path,
		unique: dfq.unique,
	}
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		CreatedAt time.Time `json:"created_at,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.DeviceFlow.Query().
//		GroupBy(deviceflow.FieldCreatedAt).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (dfq *DeviceFlowQuery) GroupBy(field string, fields ...string) *DeviceFlowGroupBy {
	grbuild := &DeviceFlowGroupBy{config: dfq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := dfq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return dfq.sqlQuery(ctx), nil
	}
	grbuild.label = deviceflow.Label
	grbuild.flds, grbuild.scan = &grbuild.fields, grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		CreatedAt time.Time `json:"created_at,omitempty"`
//	}
//
//	client.DeviceFlow.Query().
//		Select(deviceflow.FieldCreatedAt).
//		Scan(ctx, &v)
func (dfq *DeviceFlowQuery) Select(fields ...string) *DeviceFlowSelect {
	dfq.fields = append(dfq.fields, fields...)
	selbuild := &DeviceFlowSelect{DeviceFlowQuery: dfq}
	selbuild.label = deviceflow.Label
	selbuild.flds, selbuild.scan = &dfq.fields, selbuild.Scan
	return selbuild
}

// Aggregate returns a DeviceFlowSelect configured with the given aggregations.
func (dfq *DeviceFlowQuery) Aggregate(fns ...AggregateFunc) *DeviceFlowSelect {
	return dfq.Select().Aggregate(fns...)
}

func (dfq *DeviceFlowQuery) prepareQuery(ctx context.Context) error {
	for _, f := range dfq.fields {
		if !deviceflow.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if dfq.path != nil {
		prev, err := dfq.path(ctx)
		if err != nil {
			return err
		}
		dfq.sql = prev
	}
	return nil
}

func (dfq *DeviceFlowQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*DeviceFlow, error) {
	var (
		nodes = []*DeviceFlow{}
		_spec = dfq.querySpec()
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*DeviceFlow).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &DeviceFlow{config: dfq.config}
		nodes = append(nodes, node)
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, dfq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	return nodes, nil
}

func (dfq *DeviceFlowQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := dfq.querySpec()
	_spec.Node.Columns = dfq.fields
	if len(dfq.fields) > 0 {
		_spec.Unique = dfq.unique != nil && *dfq.unique
	}
	return sqlgraph.CountNodes(ctx, dfq.driver, _spec)
}

func (dfq *DeviceFlowQuery) sqlExist(ctx context.Context) (bool, error) {
	switch _, err := dfq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

func (dfq *DeviceFlowQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   deviceflow.Table,
			Columns: deviceflow.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: deviceflow.FieldID,
			},
		},
		From:   dfq.sql,
		Unique: true,
	}
	if unique := dfq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := dfq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, deviceflow.FieldID)
		for i := range fields {
			if fields[i] != deviceflow.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := dfq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := dfq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := dfq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := dfq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (dfq *DeviceFlowQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(dfq.driver.Dialect())
	t1 := builder.Table(deviceflow.Table)
	columns := dfq.fields
	if len(columns) == 0 {
		columns = deviceflow.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if dfq.sql != nil {
		selector = dfq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if dfq.unique != nil && *dfq.unique {
		selector.Distinct()
	}
	for _, p := range dfq.predicates {
		p(selector)
	}
	for _, p := range dfq.order {
		p(selector)
	}
	if offset := dfq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := dfq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// DeviceFlowGroupBy is the group-by builder for DeviceFlow entities.
type DeviceFlowGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (dfgb *DeviceFlowGroupBy) Aggregate(fns ...AggregateFunc) *DeviceFlowGroupBy {
	dfgb.fns = append(dfgb.fns, fns...)
	return dfgb
}

// Scan applies the group-by query and scans the result into the given value.
func (dfgb *DeviceFlowGroupBy) Scan(ctx context.Context, v any) error {
	query, err := dfgb.path(ctx)
	if err != nil {
		return err
	}
	dfgb.sql = query
	return dfgb.sqlScan(ctx, v)
}

func (dfgb *DeviceFlowGroupBy) sqlScan(ctx context.Context, v any) error {
	for _, f := range dfgb.fields {
		if !deviceflow.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := dfgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := dfgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (dfgb *DeviceFlowGroupBy) sqlQuery() *sql.Selector {
	selector := dfgb.sql.Select()
	aggregation := make([]string, 0, len(dfgb.fns))
	for _, fn := range dfgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(dfgb.fields)+len(dfgb.fns))
		for _, f := range dfgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(dfgb.fields...)...)
}

// DeviceFlowSelect is the builder for selecting fields of DeviceFlow entities.
type DeviceFlowSelect struct {
	*DeviceFlowQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (dfs *DeviceFlowSelect) Aggregate(fns ...AggregateFunc) *DeviceFlowSelect {
	dfs.fns = append(dfs.fns, fns...)
	return dfs
}

// Scan applies the selector query and scans the result into the given value.
func (dfs *DeviceFlowSelect) Scan(ctx context.Context, v any) error {
	if err := dfs.prepareQuery(ctx); err != nil {
		return err
	}
	dfs.sql = dfs.DeviceFlowQuery.sqlQuery(ctx)
	return dfs.sqlScan(ctx, v)
}

func (dfs *DeviceFlowSelect) sqlScan(ctx context.Context, v any) error {
	aggregation := make([]string, 0, len(dfs.fns))
	for _, fn := range dfs.fns {
		aggregation = append(aggregation, fn(dfs.sql))
	}
	switch n := len(*dfs.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		dfs.sql.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		dfs.sql.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := dfs.sql.Query()
	if err := dfs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}