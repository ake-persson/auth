package auth

type User struct {
	Username   string   `json:"username"`
	Name       string   `json:"name"`
	Mail       string   `json:"mail"`
	Groups     []string `json:"-"`
	DistrLists []string `json:"-"`
	Roles      []string `json:"roles,omitempty"`
	Renewed    int      `json:"renewed"`
}
