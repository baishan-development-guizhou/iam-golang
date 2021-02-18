package iam

import (
	"golang.org/x/oauth2"
	"sync"
	"time"
)

type TokenStore interface {
	Store(key string, tokenInfo *TokenInfo)
	Remove(key string)
	Load(key string) (tokenInfo *TokenInfo)
}

type MemoryTokenStore struct {
	store sync.Map
}

func (m *MemoryTokenStore) Store(key string, tokenInfo *TokenInfo) {
	m.store.Store(key, tokenInfo)
}

func (m *MemoryTokenStore) Load(key string) (tokenInfo *TokenInfo) {
	load, ok := m.store.LoadAndDelete(key)
	if !ok {
		return nil
	}
	return load.(*TokenInfo)
}

func (m *MemoryTokenStore) Remove(key string) {
	m.store.Delete(key)
}

type TokenInfo struct {
	AccessToken     string
	RefreshToken    string
	AccessExpireAt  time.Time
	RefreshExpireAt time.Time
}

func buildTokenInfo(token *oauth2.Token) *TokenInfo {
	expiry := token.Expiry
	issueAt := expiry.Add(time.Second * time.Duration(-token.Extra("expires_in").(float64)))
	refreshExpireAt := issueAt.Add(time.Second * time.Duration(token.Extra("refresh_expires_in").(float64)))
	return &TokenInfo{
		AccessToken:     token.AccessToken,
		RefreshToken:    token.RefreshToken,
		AccessExpireAt:  expiry,
		RefreshExpireAt: refreshExpireAt,
	}
}

func buildTokenKey(info *UserAuthorization) string {
	return info.Sub + "-" + info.AccessToken[len(info.AccessToken)-6:]
}
