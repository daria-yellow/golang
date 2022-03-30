package main

import (
	"errors"
	"sync"
)

type InMemoryUserStorage struct {
	lock    sync.RWMutex
	storage map[string]User
}

func NewInMemoryUserStorage() *InMemoryUserStorage {
	return &InMemoryUserStorage{
		lock:    sync.RWMutex{},
		storage: make(map[string]User),
	}
}

func (i *InMemoryUserStorage) Add(s string, u User) error {
	_, ok := i.storage[s]
	if ok == true {
		return errors.New("This user is already registered")
	} else {
		i.storage[s] = u
		return nil
	}
}

func (i *InMemoryUserStorage) Get(s string) (User, error) {
	_, ok := i.storage[s]
	if ok != true {
		return User{}, errors.New("This user doesn't exist")
	} else {
		return i.storage[s], nil
	}
}

func (i *InMemoryUserStorage) Update(s string, u User) error {
	_, ok := i.storage[s]
	if ok != true {
		return errors.New("This user doesn't exist")
	} else {
		i.storage[s] = u
		return nil
	}
}

func (i *InMemoryUserStorage) Delete(s string) (User, error) {
	_, ok := i.storage[s]
	if ok != true {
		return User{}, errors.New("There is no such user")
	} else {
		a := i.storage[s]
		delete(i.storage, s)
		return a, nil
	}
}

// Add should return error if user with given key (login) is already

// Update should return error if there is no such user to update
// Delete should return error if there is no such user to delete
// Delete should return deleted user
