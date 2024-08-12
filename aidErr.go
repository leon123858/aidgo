package aidgo

type AidError struct {
	Code int
	Err  string
}

func (e *AidError) Error() string {
	return e.Err
}

func NewAidCustomError(code int, err string) *AidError {
	return &AidError{
		Code: code,
		Err:  err,
	}
}

func NewBadRequestError(err string) *AidError {
	return NewAidCustomError(400, err)
}

func NewNotFoundError(err string) *AidError {
	return NewAidCustomError(404, err)
}

func NewInternalServerError(err string) *AidError {
	return NewAidCustomError(500, err)
}

func NewNotImplementedError(err string) *AidError {
	return NewAidCustomError(501, err)
}
