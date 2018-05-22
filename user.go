package auth

type User struct {
	DN       string   `json:"-"`
	UID      int      `json:"-"`
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Mail     string   `json:"mail"`
	Groups   Groups   `json:"-"`
	Roles    []string `json:"roles,omitempty"`
}

type Group struct {
	DN   string `json:"dn,omitempty"`
	GID  int    `json:"gid,omitempty"`
	Name string `json:"name"`
}

type Groups []*Group
