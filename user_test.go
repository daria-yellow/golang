package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

type parsedResponse struct {
	status int
	body   []byte
}

func createRequester(t *testing.T) func(req *http.Request, err error) parsedResponse {
	return func(req *http.Request, err error) parsedResponse {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}
		resp, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}
		return parsedResponse{res.StatusCode, resp}
	}
}

func prepareParams(t *testing.T, params map[string]interface{}) io.Reader {
	body, err := json.Marshal(params)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	return bytes.NewBuffer(body)
}

func newTestUserService() *UserService {
	return &UserService{
		repository: NewInMemoryUserStorage(),
	}
}

func assertStatus(t *testing.T, expected int, r parsedResponse) {
	if r.status != expected {
		t.Errorf("Unexpected response status. Expected: %d, actual: %d", expected, r.status)
	}
}

func assertBody(t *testing.T, expected string, r parsedResponse) {
	actual := string(r.body)
	if actual != expected {
		t.Errorf("Unexpected response body. Expected: %s, actual: %s", expected, actual)
	}
}

func TestUsers_JWT(t *testing.T) {
	doRequest := createRequester(t)
	t.Run("user does not exist", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "This user doesn't exist", resp)
	})

	t.Run("wrong password", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_2 := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts_1.Close()
		defer ts_2.Close()
		params_1 := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}
		params_2 := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "wrongpass",
		}
		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params_1)))
		resp := doRequest(http.NewRequest(http.MethodPost, ts_2.URL, prepareParams(t, params_2)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)
	})

	t.Run("register", func(t *testing.T) {
		u := newTestUserService()
		_, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 201, resp)
		assertBody(t, "registered", resp)
	})

	t.Run("register the same email", func(t *testing.T) {
		u := newTestUserService()
		_, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts_1.Close()

		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}
		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params)))
		resp_2 := doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp_2)
		assertBody(t, "This user is already registered", resp_2)
	})

	t.Run("register wrong cake", func(t *testing.T) {
		u := newTestUserService()
		_, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params_1 := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		params_2 := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake12",
		}
		resp_1 := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params_1)))
		assertStatus(t, 422, resp_1)
		assertBody(t, "Enter your cake", resp_1)

		resp_2 := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params_2)))
		assertStatus(t, 422, resp_2)
		assertBody(t, "Invalid cake: should consist only letters!", resp_2)
	})

	t.Run("register with wrong password", func(t *testing.T) {
		u := newTestUserService()
		_, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "pass",
			"favorite_cake": "cake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "Password should consist at least 8 characters", resp)
	})

	t.Run("register wrong email", func(t *testing.T) {
		u := newTestUserService()
		_, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params_1 := map[string]interface{}{
			"email":         "@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}
		params_2 := map[string]interface{}{
			"email":         "dasha@",
			"password":      "somepass",
			"favorite_cake": "cake",
		}
		params_3 := map[string]interface{}{
			"email":         "hello",
			"password":      "somepass",
			"favorite_cake": "cake",
		}
		resp_1 := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params_1)))
		assertStatus(t, 422, resp_1)
		assertBody(t, "Invalid email", resp_1)

		resp_2 := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params_2)))
		assertStatus(t, 422, resp_2)
		assertBody(t, "Invalid email", resp_2)

		resp_3 := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params_3)))
		assertStatus(t, 422, resp_3)
		assertBody(t, "Invalid email", resp_3)
	})

	t.Run("get JWT", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_2 := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts_1.Close()
		defer ts_2.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}
		user := User{
			Email:          "test@mail.com",
			PasswordDigest: "somepass",
		}
		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		token, _ := jwtService.GenearateJWT(user)
		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params)))
		resp_2 := doRequest(http.NewRequest(http.MethodPost, ts_2.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp_2)
		assertBody(t, token, resp_2)
	})

	t.Run("access to data being unauthorized", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(j.jwtAuth(u.repository, getMyData))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		resp := doRequest(http.NewRequest(http.MethodGet, ts.URL, prepareParams(t, params)))
		assertStatus(t, 401, resp)
		assertBody(t, "unauthorized", resp)
	})

	t.Run("access to data", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_2 := httptest.NewServer(j.jwtAuth(u.repository, getMyData))
		defer ts_1.Close()
		defer ts_2.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}

		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params)))

		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		user, _ := u.repository.Get("test@mail.com")
		token, _ := jwtService.GenearateJWT(user)

		req, _ := http.NewRequest(http.MethodGet, ts_2.URL, prepareParams(t, params))
		req.Header.Add("Authorization", "Bearer "+string(token))
		resp := doRequest(req, err)

		assertStatus(t, 200, resp)
		assertBody(t, user.Email+"\n"+user.FavoriteCake, resp)
	})

	t.Run("unauthorized access to cake changer", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(j.jwtAuth(u.repository, changeCakeHandler))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "brauni",
		}
		resp := doRequest(http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params)))
		assertStatus(t, 401, resp)
		assertBody(t, "unauthorized", resp)
	})

	t.Run("unauthorized access to pass changer", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(j.jwtAuth(u.repository, changePassHandler))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		resp := doRequest(http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params)))
		assertStatus(t, 401, resp)
		assertBody(t, "unauthorized", resp)
	})

	t.Run("unauthorized access to email changer", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts := httptest.NewServer(j.jwtAuth(u.repository, changeEmailHandler))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		resp := doRequest(http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params)))
		assertStatus(t, 401, resp)
		assertBody(t, "unauthorized", resp)
	})

	t.Run("invalid cake changer", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_2 := httptest.NewServer(j.jwtAuth(u.repository, changeCakeHandler))
		defer ts_1.Close()
		defer ts_2.Close()
		params_1 := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}
		params_2 := map[string]interface{}{
			"email": "test@mail.com",
		}
		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params_1)))

		user, _ := u.repository.Get("test@mail.com")
		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		token, _ := jwtService.GenearateJWT(user)

		req, _ := http.NewRequest(http.MethodPut, ts_2.URL, prepareParams(t, params_2))
		req.Header.Add("Authorization", "Bearer "+string(token))
		resp := doRequest(req, err)

		assertStatus(t, 422, resp)
		assertBody(t, "Invalid cake", resp)
	})

	t.Run("cake changer", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_2 := httptest.NewServer(j.jwtAuth(u.repository, changeCakeHandler))
		defer ts_1.Close()
		defer ts_2.Close()
		params_1 := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}
		params_2 := map[string]interface{}{
			"email":         "test@mail.com",
			"favorite_cake": "newcake",
		}

		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params_1)))

		user, _ := u.repository.Get("test@mail.com")
		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		token, _ := jwtService.GenearateJWT(user)

		req, _ := http.NewRequest(http.MethodPut, ts_2.URL, prepareParams(t, params_2))
		req.Header.Add("Authorization", "Bearer "+string(token))
		resp := doRequest(req, err)

		assertStatus(t, 201, resp)
		assertBody(t, "Your favorite cake have been changed", resp)
	})

	t.Run("invalid pass changer", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_2 := httptest.NewServer(j.jwtAuth(u.repository, changePassHandler))
		defer ts_1.Close()
		defer ts_2.Close()
		params_1 := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}
		params_2 := map[string]interface{}{
			"email": "test@mail.com",
		}

		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params_1)))

		user, _ := u.repository.Get("test@mail.com")
		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		token, _ := jwtService.GenearateJWT(user)

		req, _ := http.NewRequest(http.MethodPut, ts_2.URL, prepareParams(t, params_2))
		req.Header.Add("Authorization", "Bearer "+string(token))
		resp := doRequest(req, err)

		assertStatus(t, 422, resp)
		assertBody(t, "Invalid password", resp)
	})

	t.Run("pass changer", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_2 := httptest.NewServer(j.jwtAuth(u.repository, changePassHandler))
		defer ts_1.Close()
		defer ts_2.Close()
		params_1 := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}
		params_2 := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "mynewpass",
		}

		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params_1)))

		user, _ := u.repository.Get("test@mail.com")
		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		token, _ := jwtService.GenearateJWT(user)

		req, _ := http.NewRequest(http.MethodPut, ts_2.URL, prepareParams(t, params_2))
		req.Header.Add("Authorization", "Bearer "+string(token))
		resp := doRequest(req, err)

		assertStatus(t, 201, resp)
		assertBody(t, "Your password have been changed", resp)
	})

	t.Run("invalid email changer", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_2 := httptest.NewServer(j.jwtAuth(u.repository, changeEmailHandler))
		defer ts_1.Close()
		defer ts_2.Close()
		params_1 := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}
		params_2 := map[string]interface{}{
			"email":     "test@mail.com",
			"new email": "hello@",
		}

		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params_1)))

		user, _ := u.repository.Get("test@mail.com")
		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		token, _ := jwtService.GenearateJWT(user)

		req, _ := http.NewRequest(http.MethodPut, ts_2.URL, prepareParams(t, params_2))
		req.Header.Add("Authorization", "Bearer "+string(token))
		resp := doRequest(req, err)

		assertStatus(t, 422, resp)
		assertBody(t, "Invalid email", resp)
	})

	t.Run("email changer", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_2 := httptest.NewServer(j.jwtAuth(u.repository, changeEmailHandler))
		defer ts_1.Close()
		defer ts_2.Close()
		params_1 := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}
		params_2 := map[string]interface{}{
			"email":     "test@mail.com",
			"new email": "mynewemail@gmail.com",
		}

		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params_1)))

		user, _ := u.repository.Get("test@mail.com")
		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		token, _ := jwtService.GenearateJWT(user)

		req, _ := http.NewRequest(http.MethodPut, ts_2.URL, prepareParams(t, params_2))
		req.Header.Add("Authorization", "Bearer "+string(token))
		resp := doRequest(req, err)

		assertStatus(t, 201, resp)
		assertBody(t, "Your email have been changed", resp)
	})

	t.Run("banned authorisation", func(t *testing.T) {
		u := newTestUserService()
		Superadmin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"),
			os.Getenv("CAKE_ADMIN_CAKE"), "superadmin", false, BanHistory{}}
		u.repository.Add(Superadmin.Email, Superadmin)
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_2 := httptest.NewServer(j.jwtAuthAdmin(u.repository, banHandler))
		ts_3 := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts_1.Close()
		defer ts_2.Close()
		defer ts_3.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}

		banparams := map[string]interface{}{
			"email":  "test@mail.com",
			"reason": "because",
		}

		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params)))

		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		admin, _ := u.repository.Get(os.Getenv("CAKE_ADMIN_EMAIL"))
		token, _ := jwtService.GenearateJWT(admin)

		req, _ := http.NewRequest(http.MethodPost, ts_2.URL, prepareParams(t, banparams))
		req.Header.Add("Authorization", "Bearer "+string(token))
		doRequest(req, err)
		user, _ := u.repository.Get("test@mail.com")

		resp := doRequest(http.NewRequest(http.MethodPost, ts_3.URL, prepareParams(t, params)))
		assertStatus(t, 401, resp)
		for key, _ := range user.BanHistory.history {
			if user.BanHistory.history[key].WhoUnbanned == "" {
				assertBody(t, "Your are banned because : "+user.BanHistory.history[key].Why, resp)
			}
		}
	})
}
