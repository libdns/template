package provider

import (
	"sync"
)

func rlock(mutex sync.Locker) func() {

	if nil == mutex {
		return nil
	}

	type rlock interface {
		RUnlock()
		RLock()
	}

	// fallback to normal mutex
	var lock, unlock = mutex.Lock, mutex.Unlock

	if v, o := mutex.(rlock); o {
		lock, unlock = v.RLock, v.RUnlock
	}

	lock()

	return sync.OnceFunc(unlock)
}

func lock(mutex sync.Locker) func() {

	if nil == mutex {
		return nil
	}

	mutex.Lock()

	return sync.OnceFunc(mutex.Unlock)
}
