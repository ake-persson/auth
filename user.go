package auth

type User struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	EMail    string `json:"eMail"`
	Groups   Groups `json:"groups"`
}

type Group struct {
	Groupname string `json:"groupname"`
	Name      string `json:"name"`
}

type Groups []*Group
