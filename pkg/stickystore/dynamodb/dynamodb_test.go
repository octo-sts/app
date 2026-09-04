// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package dynamodb

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// fakeClient implements API with per-operation hooks. Unset hooks return
// empty successful responses.
type fakeClient struct {
	getItem    func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
	putItem    func(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error)
	updateItem func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error)
}

func (f *fakeClient) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if f.getItem == nil {
		return &dynamodb.GetItemOutput{}, nil
	}
	return f.getItem(in)
}

func (f *fakeClient) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if f.putItem == nil {
		return &dynamodb.PutItemOutput{}, nil
	}
	return f.putItem(in)
}

func (f *fakeClient) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	if f.updateItem == nil {
		return &dynamodb.UpdateItemOutput{}, nil
	}
	return f.updateItem(in)
}

func marshaledDoc(t *testing.T, d doc) map[string]types.AttributeValue {
	t.Helper()
	item, err := attributevalue.MarshalMap(d)
	if err != nil {
		t.Fatalf("MarshalMap: %v", err)
	}
	return item
}

func TestGetMiss(t *testing.T) {
	updates := 0
	s := New(&fakeClient{
		updateItem: func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			updates++
			return &dynamodb.UpdateItemOutput{}, nil
		},
	}, "sticky", time.Hour)

	id, ok, err := s.Get(context.Background(), "42")
	if id != 0 || ok || err != nil {
		t.Errorf("Get() = (%d, %t, %v), want (0, false, nil)", id, ok, err)
	}
	if updates != 0 {
		t.Errorf("UpdateItem called %d times on a miss, want 0", updates)
	}
}

func TestGetHitRefreshesTTL(t *testing.T) {
	var refreshed *dynamodb.UpdateItemInput
	s := New(&fakeClient{
		getItem: func(in *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			if got := aws.ToString(in.TableName); got != "sticky" {
				t.Errorf("GetItem TableName = %q, want sticky", got)
			}
			return &dynamodb.GetItemOutput{
				Item: marshaledDoc(t, doc{ID: "42", InstallationID: 777, ExpireAt: time.Now()}),
			}, nil
		},
		updateItem: func(in *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			refreshed = in
			return &dynamodb.UpdateItemOutput{}, nil
		},
	}, "sticky", time.Hour)

	lo := time.Now().Add(time.Hour).Unix()
	id, ok, err := s.Get(context.Background(), "42")
	hi := time.Now().Add(time.Hour).Unix()

	if id != 777 || !ok || err != nil {
		t.Fatalf("Get() = (%d, %t, %v), want (777, true, nil)", id, ok, err)
	}
	if refreshed == nil {
		t.Fatal("UpdateItem not called on hit")
	}
	if got := aws.ToString(refreshed.TableName); got != "sticky" {
		t.Errorf("UpdateItem TableName = %q, want sticky", got)
	}
	key, ok := refreshed.Key["id"].(*types.AttributeValueMemberS)
	if !ok || key.Value != "42" {
		t.Errorf("UpdateItem Key[id] = %#v, want S 42", refreshed.Key["id"])
	}
	if got := aws.ToString(refreshed.UpdateExpression); got != "SET expire_at = :new" {
		t.Errorf("UpdateExpression = %q", got)
	}
	if got := aws.ToString(refreshed.ConditionExpression); got != "expire_at < :new" {
		t.Errorf("ConditionExpression = %q", got)
	}
	n, ok := refreshed.ExpressionAttributeValues[":new"].(*types.AttributeValueMemberN)
	if !ok {
		t.Fatalf(":new = %#v, want N", refreshed.ExpressionAttributeValues[":new"])
	}
	epoch, err := strconv.ParseInt(n.Value, 10, 64)
	if err != nil {
		t.Fatalf(":new = %q is not an integer: %v", n.Value, err)
	}
	if epoch < lo || epoch > hi {
		t.Errorf(":new = %d, want within [%d, %d] (now+ttl)", epoch, lo, hi)
	}
}

func TestGetHitToleratesLostRefreshRace(t *testing.T) {
	s := New(&fakeClient{
		getItem: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{
				Item: marshaledDoc(t, doc{ID: "42", InstallationID: 777, ExpireAt: time.Now()}),
			}, nil
		},
		updateItem: func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			return nil, &types.ConditionalCheckFailedException{}
		},
	}, "sticky", time.Hour)

	id, ok, err := s.Get(context.Background(), "42")
	if id != 777 || !ok || err != nil {
		t.Errorf("Get() = (%d, %t, %v), want (777, true, nil) despite lost refresh race", id, ok, err)
	}
}

func TestGetHitToleratesRefreshError(t *testing.T) {
	s := New(&fakeClient{
		getItem: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{
				Item: marshaledDoc(t, doc{ID: "42", InstallationID: 777, ExpireAt: time.Now()}),
			}, nil
		},
		updateItem: func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			return nil, errors.New("throttled")
		},
	}, "sticky", time.Hour)

	id, ok, err := s.Get(context.Background(), "42")
	if id != 777 || !ok || err != nil {
		t.Errorf("Get() = (%d, %t, %v), want (777, true, nil) despite refresh error", id, ok, err)
	}
}

func TestGetError(t *testing.T) {
	boom := errors.New("boom")
	s := New(&fakeClient{
		getItem: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return nil, boom
		},
	}, "sticky", time.Hour)

	id, ok, err := s.Get(context.Background(), "42")
	if id != 0 || ok || !errors.Is(err, boom) {
		t.Errorf("Get() = (%d, %t, %v), want (0, false, boom)", id, ok, err)
	}
}

func TestGetUnmarshalError(t *testing.T) {
	s := New(&fakeClient{
		getItem: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{
				Item: map[string]types.AttributeValue{
					"installation_id": &types.AttributeValueMemberS{Value: "not-a-number"},
				},
			}, nil
		},
	}, "sticky", time.Hour)

	if _, _, err := s.Get(context.Background(), "42"); err == nil {
		t.Error("Get() err = nil, want unmarshal error")
	}
}

func TestPut(t *testing.T) {
	var got *dynamodb.PutItemInput
	s := New(&fakeClient{
		putItem: func(in *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
			got = in
			return &dynamodb.PutItemOutput{}, nil
		},
	}, "sticky", time.Hour)

	lo := time.Now().Add(time.Hour).Unix()
	if err := s.Put(context.Background(), "42", 777, "org/repo", "bot", "repo:org/mono:ref:refs/heads/main"); err != nil {
		t.Fatalf("Put() = %v", err)
	}
	hi := time.Now().Add(time.Hour).Unix()

	if got == nil {
		t.Fatal("PutItem not called")
	}
	if table := aws.ToString(got.TableName); table != "sticky" {
		t.Errorf("TableName = %q, want sticky", table)
	}

	// DynamoDB TTL only honors Number attributes holding epoch seconds;
	// a string-typed expire_at would be silently ignored.
	n, ok := got.Item["expire_at"].(*types.AttributeValueMemberN)
	if !ok {
		t.Fatalf("expire_at marshaled as %T, want *types.AttributeValueMemberN", got.Item["expire_at"])
	}
	epoch, err := strconv.ParseInt(n.Value, 10, 64)
	if err != nil {
		t.Fatalf("expire_at = %q is not an integer: %v", n.Value, err)
	}
	if epoch < lo || epoch > hi {
		t.Errorf("expire_at = %d, want within [%d, %d] (now+ttl)", epoch, lo, hi)
	}

	var d doc
	if err := attributevalue.UnmarshalMap(got.Item, &d); err != nil {
		t.Fatalf("UnmarshalMap: %v", err)
	}
	if d.ID != "42" || d.InstallationID != 777 || d.Scope != "org/repo" || d.Identity != "bot" || d.Subject != "repo:org/mono:ref:refs/heads/main" {
		t.Errorf("stored doc = %+v", d)
	}
	if d.CreatedAt.IsZero() {
		t.Error("stored doc CreatedAt is zero")
	}
}

func TestPutError(t *testing.T) {
	boom := errors.New("boom")
	s := New(&fakeClient{
		putItem: func(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
			return nil, boom
		},
	}, "sticky", time.Hour)

	if err := s.Put(context.Background(), "42", 777, "", "", ""); !errors.Is(err, boom) {
		t.Errorf("Put() = %v, want boom", err)
	}
}

func TestPutGetRoundTrip(t *testing.T) {
	items := map[string]map[string]types.AttributeValue{}
	s := New(&fakeClient{
		putItem: func(in *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
			id := in.Item["id"].(*types.AttributeValueMemberS).Value
			items[id] = in.Item
			return &dynamodb.PutItemOutput{}, nil
		},
		getItem: func(in *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			id := in.Key["id"].(*types.AttributeValueMemberS).Value
			return &dynamodb.GetItemOutput{Item: items[id]}, nil
		},
	}, "sticky", time.Hour)

	if err := s.Put(context.Background(), "42", 777, "org/repo", "bot", "subj"); err != nil {
		t.Fatalf("Put() = %v", err)
	}

	id, ok, err := s.Get(context.Background(), "42")
	if id != 777 || !ok || err != nil {
		t.Errorf("Get(42) = (%d, %t, %v), want (777, true, nil)", id, ok, err)
	}

	id, ok, err = s.Get(context.Background(), "43")
	if id != 0 || ok || err != nil {
		t.Errorf("Get(43) = (%d, %t, %v), want (0, false, nil)", id, ok, err)
	}
}
