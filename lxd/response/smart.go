package response

import (
	"database/sql"
	"errors"
	"net/http"
	"os"

	"github.com/lxc/lxd/lxd/db"
	"github.com/lxc/lxd/shared/api"
)

var httpResponseErrors = map[int][]error{
	http.StatusNotFound:  {os.ErrNotExist, sql.ErrNoRows},
	http.StatusForbidden: {os.ErrPermission},
	http.StatusConflict:  {db.ErrAlreadyDefined},
}

// SmartError returns the right error message based on err.
// It uses the stdlib errors package to unwrap the error and find the cause.
func SmartError(err error) Response {
	if err == nil {
		return EmptySyncResponse
	}

	statusCode, found := api.StatusErrorMatch(err)
	if found {
		return &errorResponse{statusCode, err.Error(), nil}
	}

	for httpStatusCode, checkErrs := range httpResponseErrors {
		for _, checkErr := range checkErrs {
			if errors.Is(err, checkErr) {
				if err != checkErr {
					// If the error has been wrapped return the top-level error message.
					return &errorResponse{httpStatusCode, err.Error(), nil}
				}

				// If the error hasn't been wrapped, replace the error message with the generic
				// HTTP status text.
				return &errorResponse{httpStatusCode, http.StatusText(httpStatusCode), nil}
			}
		}
	}

	return &errorResponse{http.StatusInternalServerError, err.Error(), nil}
}

// IsNotFoundError returns true if the error is considered a Not Found error.
func IsNotFoundError(err error) bool {
	if api.StatusErrorCheck(err, http.StatusNotFound) {
		return true
	}

	for _, checkErr := range httpResponseErrors[http.StatusNotFound] {
		if errors.Is(err, checkErr) {
			return true
		}
	}

	return false
}
