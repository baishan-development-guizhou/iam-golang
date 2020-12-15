package iam_gin

type redirectUrl struct {
	Url string `json:"url"`
}

type authorizationCode struct {
	State        string `json:"state"`
	SessionState string `json:"sessionState"`
	Code         string `json:"code"`
}

type errorResponse struct {
	Message string `json:"message"`
}
