package main

// cloud_appid_resolver.go — main-side wiring for the cloud identity-map
// resolver (appid/cloud_resolver.go, extracted P2 RA.15).

import (
	"netops/backend/appid"
	"netops/backend/cloud"
)

type cloudAppResolver = appid.CloudResolver

func newCloudAppResolver(store cloud.Store) *cloudAppResolver { return appid.NewCloudResolver(store) }
