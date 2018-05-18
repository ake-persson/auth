package auth

type User struct {
	DN       string `json:"dn,omitempty"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Mail     string `json:"mail"`
	Groups   Groups `json:"groups"`
}

type Group struct {
	DN        string `json:"dn,omitempty"`
	Groupname string `json:"groupname"`
	Name      string `json:"name"`
}

type Groups []*Group
