// SPDX-License-Identifier: MIT
package main

import (
	"fmt"
	"sync"
)

type objectKind uint8

const (
	kindContext objectKind = iota + 1
	kindParty
	kindPublicKey
	kindEvalContribution
	kindEvalSet
	kindPlaintext
	kindCiphertext
	kindShare
)

type registryEntry struct {
	kind  objectKind
	value interface{}
}

var objects = struct {
	sync.RWMutex
	next  uint64
	items map[uint64]registryEntry
}{next: 1, items: make(map[uint64]registryEntry)}

func putObject(kind objectKind, value interface{}) uint64 {
	objects.Lock()
	defer objects.Unlock()
	handle := objects.next
	objects.next++
	objects.items[handle] = registryEntry{kind: kind, value: value}
	return handle
}

func getObject(handle uint64, kind objectKind) (interface{}, error) {
	objects.RLock()
	entry, ok := objects.items[handle]
	objects.RUnlock()
	if !ok {
		return nil, fmt.Errorf("closed or unknown native handle %d", handle)
	}
	if entry.kind != kind {
		return nil, fmt.Errorf("native handle %d has kind %d, expected %d", handle, entry.kind, kind)
	}
	return entry.value, nil
}

func getAnyObject(handle uint64) (registryEntry, error) {
	objects.RLock()
	entry, ok := objects.items[handle]
	objects.RUnlock()
	if !ok {
		return registryEntry{}, fmt.Errorf("closed or unknown native handle %d", handle)
	}
	return entry, nil
}

func releaseObject(handle uint64) error {
	objects.Lock()
	entry, ok := objects.items[handle]
	if ok {
		delete(objects.items, handle)
	}
	objects.Unlock()
	if !ok {
		return fmt.Errorf("closed or unknown native handle %d", handle)
	}
	if entry.kind == kindParty {
		zeroParty(entry.value.(*nativeParty))
	}
	return nil
}

func liveObjectCount() uint64 {
	objects.RLock()
	defer objects.RUnlock()
	return uint64(len(objects.items))
}
