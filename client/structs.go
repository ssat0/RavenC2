package main

type Client struct {
	ClientID string `json:"clientID"`
	OS       string `json:"os"`
	Hostname string `json:"hostname"`
	BuildID  string `json:"buildID"`
}

type Command struct {
	Command string `json:"command"`
}
