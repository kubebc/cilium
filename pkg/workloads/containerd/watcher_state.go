// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package containerd

import (
	"github.com/cilium/cilium/pkg/lock"

	dTypesEvents "github.com/docker/engine-api/types/events"
)

// watcherState holds global close flag, per-container queues for events and ignore toggles
type watcherState struct {
	lock.Mutex

	eventQueueBufferSize int
	closed               bool
	events               map[string]chan dTypesEvents.Message
}

func newWatcherState(eventQueueBufferSize int) *watcherState {
	return &watcherState{
		eventQueueBufferSize: eventQueueBufferSize,
		events:               make(map[string]chan dTypesEvents.Message),
	}
}

// enqueueByContainerID starts a handler for this container, if needed, and
// enqueues a copy of the event if it is non-nil. Passing in a nil event will
// only start the handler.
func (ws *watcherState) enqueueByContainerID(containerID string, e *dTypesEvents.Message) {
	ws.Lock()
	defer ws.Unlock()

	if _, found := ws.events[containerID]; !found {
		q := make(chan dTypesEvents.Message, eventQueueBufferSize)
		ws.events[containerID] = q
		go processContainerEvents(q)
	}

	if e != nil {
		ws.events[containerID] <- *e
	}
}

func (ws *watcherState) handlingContainerID(id string) bool {
	ws.Lock()
	defer ws.Unlock()

	_, handled := ws.events[id]
	return handled
}

func (ws *watcherState) reapEmpty() {
	ws.Lock()
	defer ws.Unlock()

	for id, q := range ws.events {
		if len(q) == 0 {
			close(q)
			delete(ws.events, id)
		}
	}
}
