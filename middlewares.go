// This package contains my own custom middlewares for mux, such as IsAuthenticated
package middlewares

import (
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/grebett/json"
	"github.com/grebett/validation"
)

//***********************************************************************************
//                                 MIDDLEWARES
//***********************************************************************************

// IsAuthenticated middleware finds in the session within the provided cookiestore if the user is authenticated AND if the account is verified
type Is struct {
	What        string
	Store       *sessions.CookieStore
	SessionName string
	Next        func(http.ResponseWriter, *http.Request)
}

// With this method, IsAuthenticated implements the handler interface and can be used with http.Handle (or other mux like functions)
func (middleware Is) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	session, _ := middleware.Store.Get(req, middleware.SessionName)
	errors := make([]*validation.DataError, 0)
	adjectives := strings.Split(middleware.What, "/")

	for _, adjective := range adjectives {
		switch adjective {
		case "authenticated":
			if session.Values["username"] == nil {
				errors = append(errors, &validation.DataError{Type: "Authentication error", Reason: "This route needs authentication."})
				errorResponse(res, http.StatusUnauthorized, errors)
				return
			}
		case "verified":
			if session.Values["isVerified"] == false {
				errors = append(errors, &validation.DataError{Type: "Authentication error", Reason: "This route is forbidden for unverified users."})
				errorResponse(res, http.StatusForbidden, errors)
				return
			}
		case "admin":
			if session.Values["role"] != "admin" {
				errors = append(errors, &validation.DataError{Type: "Authentication error", Reason: "This route is forbidden for non admin users."})
				errorResponse(res, http.StatusForbidden, errors)
				return
			}
		case "author":
			if session.Values["isAuthor"] == false {
				errors = append(errors, &validation.DataError{Type: "Authentication error", Reason: "This route is forbidden for non author users."})
				errorResponse(res, http.StatusForbidden, errors)
				return
			}
		case "author|admin":
			if session.Values["isAuthor"] == false && session.Values["role"] != "admin" {
				errors = append(errors, &validation.DataError{Type: "Authentication error", Reason: "This route is forbidden for non author users."})
				errorResponse(res, http.StatusForbidden, errors)
				return
			}
		}
	}
	middleware.Next(res, req)
}

//***********************************************************************************
//                                   HELPERS
//***********************************************************************************

func errorResponse(res http.ResponseWriter, statusCode int, errors []*validation.DataError) {
	encoded, _ := json.Encode(map[string][]*validation.DataError{
		"errors": errors,
	})

	httpResponse(
		res,
		map[string]string{"Content-Type": "application/json"},
		statusCode,
		encoded,
	)
}

func httpResponse(res http.ResponseWriter, headers map[string]string, statusCode int, data []byte) {
	for key, value := range headers {
		res.Header().Set(key, value)
	}
	res.WriteHeader(statusCode)
	res.Write(data)
}
