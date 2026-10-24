package sub

import (
	"strings"

	"github.com/nuomiiiii/lite/database/clients"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/store"
)

func ForUser(st *store.Store, user models.NodeUser) ([]Node, error) {
	grants, err := st.ListGrants(user.ID)
	if err != nil {
		return nil, err
	}
	granted := make(map[string]bool, len(grants))
	for _, g := range grants {
		granted[g.InboundID] = true
	}
	inbounds, err := st.ListInbounds("")
	if err != nil {
		return nil, err
	}
	creds, err := st.ListCredentials(user.ID)
	if err != nil {
		return nil, err
	}
	certs, err := st.ListCerts("")
	if err != nil {
		return nil, err
	}
	return AssembleWithCerts(user, inbounds, creds, granted, nodeShareHosts(inbounds, granted), certs), nil
}

func nodeShareHosts(inbounds []models.Inbound, granted map[string]bool) map[string]string {
	hosts := map[string]string{}
	for _, in := range inbounds {
		if granted != nil && !granted[in.ID] {
			continue
		}
		if _, ok := hosts[in.NodeUUID]; ok {
			continue
		}
		client, err := clients.GetClientByUUID(in.NodeUUID)
		if err != nil {
			continue
		}
		host := strings.TrimSpace(client.IPv4)
		if host == "" {
			host = strings.TrimSpace(client.IPv6)
		}
		if host != "" {
			hosts[in.NodeUUID] = host
		}
	}
	return hosts
}
