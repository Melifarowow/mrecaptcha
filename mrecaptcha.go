package mrecaptcha

import (
	"encoding/json"
	"log"

	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type RecaptchaResponse struct {
	Success     bool      `json:"success"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	//ErrorCodes  []int     `json:"error-codes,string,omitempty"`
}

func RecaptchaCheck(req *http.Request, secret string, recaptchaResponse string) (bool, error) {
	client := http.Client{}
	resp, err := client.PostForm("https://www.google.com/recaptcha/api/siteverify",
		url.Values{
			"secret":   {secret},
			"response": {recaptchaResponse},
			"remoteip": {req.RemoteAddr},
		})
	if err != nil {
		log.Printf("Captcha post error: %+v", err)
		return false, err
	}
	defer resp.Body.Close()
	rr := new(RecaptchaResponse)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Captcha read error: could not read body: %+v", err)
		return false, err
	}
	err = json.Unmarshal(body, &rr)
	if err != nil {
		log.Printf("Captcha JSON error: %s", err)
		return false, err
	}
	return rr.Success, nil
}
