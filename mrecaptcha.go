package mrecaptcha

import (
	"encoding/json"

	"google.golang.org/appengine"
	glog "google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"

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
	c := appengine.NewContext(req)
	client := urlfetch.Client(c)
	resp, err := client.PostForm("https://www.google.com/recaptcha/api/siteverify",
		url.Values{
			"secret":   {secret},
			"response": {recaptchaResponse},
			"remoteip": {req.RemoteAddr},
		})
	if err != nil {
		glog.Errorf(c, "Captcha post error: %+v", err)
		return false, err
	}
	defer resp.Body.Close()
	rr := new(RecaptchaResponse)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		glog.Errorf(c, "Captcha read error: could not read body: %+v", err)
		return false, err
	}
	err = json.Unmarshal(body, &rr)
	if err != nil {
		glog.Errorf(c, "Captcha JSON error: %s", err)
		return false, err
	}
	return rr.Success, nil
}
