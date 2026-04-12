package handler

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/slimrmm/slimrmm-agent/internal/i18n"
	"github.com/slimrmm/slimrmm-agent/internal/services/registry"
)

// Registry request types

type registryListRequest struct {
	Hive string `json:"hive"`
	Path string `json:"path"`
}

type registryCreateKeyRequest struct {
	Hive string `json:"hive"`
	Path string `json:"path"`
}

type registryDeleteKeyRequest struct {
	Hive string `json:"hive"`
	Path string `json:"path"`
}

type registryRenameKeyRequest struct {
	Hive    string `json:"hive"`
	Path    string `json:"path"`
	NewName string `json:"new_name"`
}

type registrySetValueRequest struct {
	Hive      string      `json:"hive"`
	Path      string      `json:"path"`
	Name      string      `json:"name"`
	ValueType string      `json:"type"`
	Data      interface{} `json:"data"`
}

type registryDeleteValueRequest struct {
	Hive string `json:"hive"`
	Path string `json:"path"`
	Name string `json:"name"`
}

type registryRenameValueRequest struct {
	Hive    string `json:"hive"`
	Path    string `json:"path"`
	OldName string `json:"old_name"`
	NewName string `json:"new_name"`
}

type registrySearchRequest struct {
	Hive       string `json:"hive"`
	Path       string `json:"path"`
	Query      string `json:"query"`
	MaxResults int    `json:"max_results"`
}

// registryService returns the default registry service singleton.
func registryService() registry.Service {
	return registry.GetDefault()
}

func (h *Handler) handleRegistryList(ctx context.Context, data json.RawMessage) (interface{}, error) {
	req, err := unmarshalRequest[registryListRequest](data)
	if err != nil {
		return nil, err
	}

	svc := registryService()
	if !svc.IsAvailable() {
		return nil, fmt.Errorf("%s: registry operations are only available on Windows", i18n.MsgInvalidRequest)
	}

	return svc.ListKey(ctx, req.Hive, req.Path)
}

func (h *Handler) handleRegistrySearch(ctx context.Context, data json.RawMessage) (interface{}, error) {
	req, err := unmarshalRequest[registrySearchRequest](data)
	if err != nil {
		return nil, err
	}

	svc := registryService()
	if !svc.IsAvailable() {
		return nil, fmt.Errorf("%s: registry operations are only available on Windows", i18n.MsgInvalidRequest)
	}

	maxResults := req.MaxResults
	if maxResults <= 0 {
		maxResults = 100
	}

	return svc.SearchKey(ctx, req.Hive, req.Path, req.Query, maxResults)
}

func (h *Handler) handleRegistryCreateKey(ctx context.Context, data json.RawMessage) (interface{}, error) {
	req, err := unmarshalRequest[registryCreateKeyRequest](data)
	if err != nil {
		return nil, err
	}

	svc := registryService()
	if !svc.IsAvailable() {
		return nil, fmt.Errorf("%s: registry operations are only available on Windows", i18n.MsgInvalidRequest)
	}

	if err := svc.CreateKey(ctx, req.Hive, req.Path); err != nil {
		return nil, err
	}

	return map[string]string{"status": "created", "hive": req.Hive, "path": req.Path}, nil
}

func (h *Handler) handleRegistryDeleteKey(ctx context.Context, data json.RawMessage) (interface{}, error) {
	req, err := unmarshalRequest[registryDeleteKeyRequest](data)
	if err != nil {
		return nil, err
	}

	svc := registryService()
	if !svc.IsAvailable() {
		return nil, fmt.Errorf("%s: registry operations are only available on Windows", i18n.MsgInvalidRequest)
	}

	if err := svc.DeleteKey(ctx, req.Hive, req.Path); err != nil {
		return nil, err
	}

	return map[string]string{"status": "deleted", "hive": req.Hive, "path": req.Path}, nil
}

func (h *Handler) handleRegistryRenameKey(ctx context.Context, data json.RawMessage) (interface{}, error) {
	req, err := unmarshalRequest[registryRenameKeyRequest](data)
	if err != nil {
		return nil, err
	}

	svc := registryService()
	if !svc.IsAvailable() {
		return nil, fmt.Errorf("%s: registry operations are only available on Windows", i18n.MsgInvalidRequest)
	}

	if err := svc.RenameKey(ctx, req.Hive, req.Path, req.NewName); err != nil {
		return nil, err
	}

	return map[string]string{"status": "renamed", "hive": req.Hive, "path": req.Path, "new_name": req.NewName}, nil
}

func (h *Handler) handleRegistrySetValue(ctx context.Context, data json.RawMessage) (interface{}, error) {
	req, err := unmarshalRequest[registrySetValueRequest](data)
	if err != nil {
		return nil, err
	}

	svc := registryService()
	if !svc.IsAvailable() {
		return nil, fmt.Errorf("%s: registry operations are only available on Windows", i18n.MsgInvalidRequest)
	}

	if err := svc.SetValue(ctx, req.Hive, req.Path, req.Name, req.ValueType, req.Data); err != nil {
		return nil, err
	}

	return map[string]string{"status": "set", "hive": req.Hive, "path": req.Path, "name": req.Name}, nil
}

func (h *Handler) handleRegistryDeleteValue(ctx context.Context, data json.RawMessage) (interface{}, error) {
	req, err := unmarshalRequest[registryDeleteValueRequest](data)
	if err != nil {
		return nil, err
	}

	svc := registryService()
	if !svc.IsAvailable() {
		return nil, fmt.Errorf("%s: registry operations are only available on Windows", i18n.MsgInvalidRequest)
	}

	if err := svc.DeleteValue(ctx, req.Hive, req.Path, req.Name); err != nil {
		return nil, err
	}

	return map[string]string{"status": "deleted", "hive": req.Hive, "path": req.Path, "name": req.Name}, nil
}

func (h *Handler) handleRegistryRenameValue(ctx context.Context, data json.RawMessage) (interface{}, error) {
	req, err := unmarshalRequest[registryRenameValueRequest](data)
	if err != nil {
		return nil, err
	}

	svc := registryService()
	if !svc.IsAvailable() {
		return nil, fmt.Errorf("%s: registry operations are only available on Windows", i18n.MsgInvalidRequest)
	}

	if err := svc.RenameValue(ctx, req.Hive, req.Path, req.OldName, req.NewName); err != nil {
		return nil, err
	}

	return map[string]string{"status": "renamed", "hive": req.Hive, "path": req.Path, "old_name": req.OldName, "new_name": req.NewName}, nil
}
