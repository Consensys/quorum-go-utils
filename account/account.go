package account

import "net/url"

// Account is a combination of Quorum address and location URL
type Account struct {
	Address Address
	URL     *url.URL
}
