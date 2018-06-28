package auth

type User struct {
	UUID       string   `json:"uuid,omitempty"`
	Username   string   `json:"username"`
	Name       string   `json:"name"`
	Title      string   `json:"-"` // `json:"title"`
	Descr      string   `json:"-"` // `json:"descr"`
	Mail       string   `json:"mail"`
	Company    string   `json:"-"` // `json:"company"`
	Department string   `json:"-"` // `json:"department"`
	Location   string   `json:"-"` // `json:"location"`
	State      string   `json:"-"` // `json:"state"`
	Country    string   `json:"-"` // `json:"country"`
	Groups     []string `json:"-"` // `json:"groups"`
	DistrLists []string `json:"-"` // `json:"distrLists"`
	Roles      []string `json:"roles,omitempty"`
}
