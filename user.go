package auth

type User struct {
	DN       string   `json:"-"`
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Mail     string   `json:"mail"`
	UID      int      `json:"uid,omitempty"`
	GID      int      `json:"gid,omitempty"`
	Home     string   `json:"home,omitempty"`
	Shell    string   `json:"shell,omitempty"`
	Groups   Groups   `json:"-"`
	Roles    []string `json:"roles,omitempty"`
	Renewed  int      `json:"renewed"`
}

type Group struct {
	DN   string
	Name string
	GID  int
}

type Groups []*Group
