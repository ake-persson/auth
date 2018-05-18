package auth

type User struct {
	DN       string `json:"dn,omitempty"`
	UID      int    `json:"uid,omitempty"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Mail     string `json:"mail"`
	Groups   Groups `json:"groups"`
}

type Group struct {
	DN   string `json:"dn,omitempty"`
	GID  int    `json:"gid,omitempty"`
	Name string `json:"name"`
}

type Groups []*Group
