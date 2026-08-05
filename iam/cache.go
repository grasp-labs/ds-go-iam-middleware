package iam

// Cache stores raw policy documents between requests.
//
// The method set is bigcache's, so *bigcache.BigCache satisfies it directly and
// this module does not depend on bigcache.
type Cache interface {
	Get(key string) ([]byte, error)
	Set(key string, entry []byte) error
	Delete(key string) error
}
