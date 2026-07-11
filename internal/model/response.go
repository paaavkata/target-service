package model

// Response is the standard JSON envelope returned by every endpoint.
type Response struct {
	Status  string      `json:"status"` // "success" | "error"
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}
