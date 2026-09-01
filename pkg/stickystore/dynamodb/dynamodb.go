// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package dynamodb

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/chainguard-dev/clog"
)

// API is the subset of the DynamoDB client used by Store. It is satisfied
// by *dynamodb.Client and faked in tests.
type API interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

type Store struct {
	client API
	table  string
	ttl    time.Duration
}

type doc struct {
	ID             string    `dynamodbav:"id"`
	InstallationID int64     `dynamodbav:"installation_id"`
	Scope          string    `dynamodbav:"scope"`
	Identity       string    `dynamodbav:"identity"`
	Subject        string    `dynamodbav:"subject"`
	CreatedAt      time.Time `dynamodbav:"created_at"`
	ExpireAt       time.Time `dynamodbav:"expire_at,unixtime"`
}

// New creates a DynamoDB-backed sticky store. Items are keyed by the "id"
// string partition key in the given table, with TTL managed via the
// expire_at attribute (the table must have TTL enabled on expire_at).
func New(client API, table string, ttl time.Duration) *Store {
	return &Store{
		client: client,
		table:  table,
		ttl:    ttl,
	}
}

// Get returns the persisted installation ID for key. Returns ok=false on
// cache miss. Refreshes the item's expire_at on every hit so active
// mappings never reach the TTL.
func (s *Store) Get(ctx context.Context, key string) (int64, bool, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            itemKey(key),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return 0, false, err
	}
	if len(out.Item) == 0 {
		return 0, false, nil
	}

	var d doc
	if err := attributevalue.UnmarshalMap(out.Item, &d); err != nil {
		return 0, false, err
	}

	newExpire := time.Now().Add(s.ttl).Unix()
	if _, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.table),
		Key:                 itemKey(key),
		UpdateExpression:    aws.String("SET expire_at = :new"),
		ConditionExpression: aws.String("expire_at < :new"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":new": &types.AttributeValueMemberN{Value: strconv.FormatInt(newExpire, 10)},
		},
	}); err != nil {
		var ccf *types.ConditionalCheckFailedException
		if !errors.As(err, &ccf) {
			clog.FromContext(ctx).Warnf("stickystore: failed to refresh TTL for key %s: %v", key, err)
		}
	}

	return d.InstallationID, true, nil
}

// Put persists a sticky mapping. Overwrites any existing item for the key.
// scope, identity, and subject are stored for operator debuggability.
func (s *Store) Put(ctx context.Context, key string, installationID int64, scope, identity, subject string) error {
	now := time.Now()
	item, err := attributevalue.MarshalMap(doc{
		ID:             key,
		InstallationID: installationID,
		Scope:          scope,
		Identity:       identity,
		Subject:        subject,
		CreatedAt:      now,
		ExpireAt:       now.Add(s.ttl),
	})
	if err != nil {
		return err
	}
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.table),
		Item:      item,
	})
	return err
}

func itemKey(key string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"id": &types.AttributeValueMemberS{Value: key},
	}
}
