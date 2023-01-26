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
	"github.com/loopholelabs/auth/internal/ent/googleflow"
	"github.com/loopholelabs/auth/internal/ent/predicate"
)

// GoogleFlowQuery is the builder for querying GoogleFlow entities.
type GoogleFlowQuery struct {
	config
	limit      *int
	offset     *int
	unique     *bool
	order      []OrderFunc
	fields     []string
	predicates []predicate.GoogleFlow
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the GoogleFlowQuery builder.
func (gfq *GoogleFlowQuery) Where(ps ...predicate.GoogleFlow) *GoogleFlowQuery {
	gfq.predicates = append(gfq.predicates, ps...)
	return gfq
}

// Limit adds a limit step to the query.
func (gfq *GoogleFlowQuery) Limit(limit int) *GoogleFlowQuery {
	gfq.limit = &limit
	return gfq
}

// Offset adds an offset step to the query.
func (gfq *GoogleFlowQuery) Offset(offset int) *GoogleFlowQuery {
	gfq.offset = &offset
	return gfq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (gfq *GoogleFlowQuery) Unique(unique bool) *GoogleFlowQuery {
	gfq.unique = &unique
	return gfq
}

// Order adds an order step to the query.
func (gfq *GoogleFlowQuery) Order(o ...OrderFunc) *GoogleFlowQuery {
	gfq.order = append(gfq.order, o...)
	return gfq
}

// First returns the first GoogleFlow entity from the query.
// Returns a *NotFoundError when no GoogleFlow was found.
func (gfq *GoogleFlowQuery) First(ctx context.Context) (*GoogleFlow, error) {
	nodes, err := gfq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{googleflow.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (gfq *GoogleFlowQuery) FirstX(ctx context.Context) *GoogleFlow {
	node, err := gfq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first GoogleFlow ID from the query.
// Returns a *NotFoundError when no GoogleFlow ID was found.
func (gfq *GoogleFlowQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = gfq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{googleflow.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (gfq *GoogleFlowQuery) FirstIDX(ctx context.Context) int {
	id, err := gfq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single GoogleFlow entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one GoogleFlow entity is found.
// Returns a *NotFoundError when no GoogleFlow entities are found.
func (gfq *GoogleFlowQuery) Only(ctx context.Context) (*GoogleFlow, error) {
	nodes, err := gfq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{googleflow.Label}
	default:
		return nil, &NotSingularError{googleflow.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (gfq *GoogleFlowQuery) OnlyX(ctx context.Context) *GoogleFlow {
	node, err := gfq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only GoogleFlow ID in the query.
// Returns a *NotSingularError when more than one GoogleFlow ID is found.
// Returns a *NotFoundError when no entities are found.
func (gfq *GoogleFlowQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = gfq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{googleflow.Label}
	default:
		err = &NotSingularError{googleflow.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (gfq *GoogleFlowQuery) OnlyIDX(ctx context.Context) int {
	id, err := gfq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of GoogleFlows.
func (gfq *GoogleFlowQuery) All(ctx context.Context) ([]*GoogleFlow, error) {
	if err := gfq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return gfq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (gfq *GoogleFlowQuery) AllX(ctx context.Context) []*GoogleFlow {
	nodes, err := gfq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of GoogleFlow IDs.
func (gfq *GoogleFlowQuery) IDs(ctx context.Context) ([]int, error) {
	var ids []int
	if err := gfq.Select(googleflow.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (gfq *GoogleFlowQuery) IDsX(ctx context.Context) []int {
	ids, err := gfq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (gfq *GoogleFlowQuery) Count(ctx context.Context) (int, error) {
	if err := gfq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return gfq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (gfq *GoogleFlowQuery) CountX(ctx context.Context) int {
	count, err := gfq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (gfq *GoogleFlowQuery) Exist(ctx context.Context) (bool, error) {
	if err := gfq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return gfq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (gfq *GoogleFlowQuery) ExistX(ctx context.Context) bool {
	exist, err := gfq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the GoogleFlowQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (gfq *GoogleFlowQuery) Clone() *GoogleFlowQuery {
	if gfq == nil {
		return nil
	}
	return &GoogleFlowQuery{
		config:     gfq.config,
		limit:      gfq.limit,
		offset:     gfq.offset,
		order:      append([]OrderFunc{}, gfq.order...),
		predicates: append([]predicate.GoogleFlow{}, gfq.predicates...),
		// clone intermediate query.
		sql:    gfq.sql.Clone(),
		path:   gfq.path,
		unique: gfq.unique,
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
//	client.GoogleFlow.Query().
//		GroupBy(googleflow.FieldCreatedAt).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (gfq *GoogleFlowQuery) GroupBy(field string, fields ...string) *GoogleFlowGroupBy {
	grbuild := &GoogleFlowGroupBy{config: gfq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := gfq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return gfq.sqlQuery(ctx), nil
	}
	grbuild.label = googleflow.Label
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
//	client.GoogleFlow.Query().
//		Select(googleflow.FieldCreatedAt).
//		Scan(ctx, &v)
func (gfq *GoogleFlowQuery) Select(fields ...string) *GoogleFlowSelect {
	gfq.fields = append(gfq.fields, fields...)
	selbuild := &GoogleFlowSelect{GoogleFlowQuery: gfq}
	selbuild.label = googleflow.Label
	selbuild.flds, selbuild.scan = &gfq.fields, selbuild.Scan
	return selbuild
}

// Aggregate returns a GoogleFlowSelect configured with the given aggregations.
func (gfq *GoogleFlowQuery) Aggregate(fns ...AggregateFunc) *GoogleFlowSelect {
	return gfq.Select().Aggregate(fns...)
}

func (gfq *GoogleFlowQuery) prepareQuery(ctx context.Context) error {
	for _, f := range gfq.fields {
		if !googleflow.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if gfq.path != nil {
		prev, err := gfq.path(ctx)
		if err != nil {
			return err
		}
		gfq.sql = prev
	}
	return nil
}

func (gfq *GoogleFlowQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*GoogleFlow, error) {
	var (
		nodes = []*GoogleFlow{}
		_spec = gfq.querySpec()
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*GoogleFlow).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &GoogleFlow{config: gfq.config}
		nodes = append(nodes, node)
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, gfq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	return nodes, nil
}

func (gfq *GoogleFlowQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := gfq.querySpec()
	_spec.Node.Columns = gfq.fields
	if len(gfq.fields) > 0 {
		_spec.Unique = gfq.unique != nil && *gfq.unique
	}
	return sqlgraph.CountNodes(ctx, gfq.driver, _spec)
}

func (gfq *GoogleFlowQuery) sqlExist(ctx context.Context) (bool, error) {
	switch _, err := gfq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

func (gfq *GoogleFlowQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   googleflow.Table,
			Columns: googleflow.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: googleflow.FieldID,
			},
		},
		From:   gfq.sql,
		Unique: true,
	}
	if unique := gfq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := gfq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, googleflow.FieldID)
		for i := range fields {
			if fields[i] != googleflow.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := gfq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := gfq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := gfq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := gfq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (gfq *GoogleFlowQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(gfq.driver.Dialect())
	t1 := builder.Table(googleflow.Table)
	columns := gfq.fields
	if len(columns) == 0 {
		columns = googleflow.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if gfq.sql != nil {
		selector = gfq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if gfq.unique != nil && *gfq.unique {
		selector.Distinct()
	}
	for _, p := range gfq.predicates {
		p(selector)
	}
	for _, p := range gfq.order {
		p(selector)
	}
	if offset := gfq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := gfq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// GoogleFlowGroupBy is the group-by builder for GoogleFlow entities.
type GoogleFlowGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (gfgb *GoogleFlowGroupBy) Aggregate(fns ...AggregateFunc) *GoogleFlowGroupBy {
	gfgb.fns = append(gfgb.fns, fns...)
	return gfgb
}

// Scan applies the group-by query and scans the result into the given value.
func (gfgb *GoogleFlowGroupBy) Scan(ctx context.Context, v any) error {
	query, err := gfgb.path(ctx)
	if err != nil {
		return err
	}
	gfgb.sql = query
	return gfgb.sqlScan(ctx, v)
}

func (gfgb *GoogleFlowGroupBy) sqlScan(ctx context.Context, v any) error {
	for _, f := range gfgb.fields {
		if !googleflow.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := gfgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := gfgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (gfgb *GoogleFlowGroupBy) sqlQuery() *sql.Selector {
	selector := gfgb.sql.Select()
	aggregation := make([]string, 0, len(gfgb.fns))
	for _, fn := range gfgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(gfgb.fields)+len(gfgb.fns))
		for _, f := range gfgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(gfgb.fields...)...)
}

// GoogleFlowSelect is the builder for selecting fields of GoogleFlow entities.
type GoogleFlowSelect struct {
	*GoogleFlowQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (gfs *GoogleFlowSelect) Aggregate(fns ...AggregateFunc) *GoogleFlowSelect {
	gfs.fns = append(gfs.fns, fns...)
	return gfs
}

// Scan applies the selector query and scans the result into the given value.
func (gfs *GoogleFlowSelect) Scan(ctx context.Context, v any) error {
	if err := gfs.prepareQuery(ctx); err != nil {
		return err
	}
	gfs.sql = gfs.GoogleFlowQuery.sqlQuery(ctx)
	return gfs.sqlScan(ctx, v)
}

func (gfs *GoogleFlowSelect) sqlScan(ctx context.Context, v any) error {
	aggregation := make([]string, 0, len(gfs.fns))
	for _, fn := range gfs.fns {
		aggregation = append(aggregation, fn(gfs.sql))
	}
	switch n := len(*gfs.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		gfs.sql.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		gfs.sql.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := gfs.sql.Query()
	if err := gfs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
