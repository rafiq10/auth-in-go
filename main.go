package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var secret = "bobas987"
var salt = "mysalt"

func main() {
	http.HandleFunc("/", login)
	http.HandleFunc("/submit", submit)
	http.ListenAndServe(":8079", nil)
}

func login(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		c = &http.Cookie{}
	}
	isEqual := true
	xs := strings.SplitN(c.Value, "|", 2)
	if len(xs) == 2 {
		cCode := xs[0]
		cEmail := xs[1]

		code := getCode(cEmail)
		isEqual = hmac.Equal([]byte(cCode), []byte(code))
	}

	message := "Not Logged In"
	if isEqual {
		message = "Logged In"
	}
	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Document</title>
	</head>
	<body>
	<p>Cookie value: ` + c.Value + `</p>
	<p>` + message + `</p>
	<form action="submit" method="post">
        <input type="email" name="email">
        <input type="submit"> 
    </form>
	</body>
	</html>`
	io.WriteString(w, html)
}

func submit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}

	email := r.FormValue("email")
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
	code := getCode(email)

	c := http.Cookie{
		Name:  "session",
		Value: code + "|" + email,
	}
	http.SetCookie(w, &c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getCode(msg string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(msg))
	return fmt.Sprintf("%x", h.Sum([]byte(salt)))
}
