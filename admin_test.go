package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
)

func TestAdmin_JWT(t *testing.T) {
	doRequest := createRequester(t)
	t.Run("ban user", func(t *testing.T) {
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
		defer ts_1.Close()
		defer ts_2.Close()
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
		resp := doRequest(req, err)
		user, _ := u.repository.Get("test@mail.com")
		assertStatus(t, 201, resp)
		assertBody(t, "The user have been banned bacause: "+user.BanHistory.Why, resp)
	})

	t.Run("ban unexisted user", func(t *testing.T) {
		u := newTestUserService()
		Superadmin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"),
			os.Getenv("CAKE_ADMIN_CAKE"), "superadmin", false, BanHistory{}}
		u.repository.Add(Superadmin.Email, Superadmin)
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(j.jwtAuthAdmin(u.repository, banHandler))
		defer ts_1.Close()

		banparams := map[string]interface{}{
			"email":  "test@mail.com",
			"reason": "because",
		}

		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		admin, _ := u.repository.Get(os.Getenv("CAKE_ADMIN_EMAIL"))
		token, _ := jwtService.GenearateJWT(admin)

		req, _ := http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, banparams))
		req.Header.Add("Authorization", "Bearer "+string(token))
		resp := doRequest(req, err)
		assertStatus(t, 401, resp)
		assertBody(t, "This user doesn't exist", resp)
	})

	t.Run("admin ban admin", func(t *testing.T) {
		u := newTestUserService()
		Superadmin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"),
			os.Getenv("CAKE_ADMIN_CAKE"), "superadmin", false, BanHistory{}}
		u.repository.Add(Superadmin.Email, Superadmin)
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_2 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_3 := httptest.NewServer(j.jwtAuthAdmin(u.repository, promoteHandler))
		ts_4 := httptest.NewServer(j.jwtAuthAdmin(u.repository, promoteHandler))
		ts_5 := httptest.NewServer(j.jwtAuthAdmin(u.repository, banHandler))

		defer ts_1.Close()
		defer ts_2.Close()
		defer ts_3.Close()
		defer ts_4.Close()
		defer ts_5.Close()

		reg1 := map[string]interface{}{
			"email":         "test1@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}

		reg2 := map[string]interface{}{
			"email":         "test2@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}

		promoteparams1 := map[string]interface{}{
			"email": "test1@mail.com",
		}

		promoteparams2 := map[string]interface{}{
			"email": "test2@mail.com",
		}

		ban := map[string]interface{}{
			"email":  "test2@mail.com",
			"reason": "because",
		}

		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, reg1)))
		doRequest(http.NewRequest(http.MethodPost, ts_2.URL, prepareParams(t, reg2)))

		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		admin, _ := u.repository.Get(os.Getenv("CAKE_ADMIN_EMAIL"))
		token, _ := jwtService.GenearateJWT(admin)

		req1, _ := http.NewRequest(http.MethodPost, ts_3.URL, prepareParams(t, promoteparams1))
		req1.Header.Add("Authorization", "Bearer "+string(token))
		doRequest(req1, err)

		user, _ := u.repository.Get("test1@mail.com")
		user_token, _ := jwtService.GenearateJWT(user)

		req2, _ := http.NewRequest(http.MethodPost, ts_4.URL, prepareParams(t, promoteparams2))
		req2.Header.Add("Authorization", "Bearer "+string(token))
		doRequest(req2, err)

		req, _ := http.NewRequest(http.MethodPost, ts_5.URL, prepareParams(t, ban))
		req.Header.Add("Authorization", "Bearer "+string(user_token))
		resp := doRequest(req, err)

		assertStatus(t, 401, resp)
		assertBody(t, "Only superadmin can ban admin!", resp)
	})

	t.Run("admin unban admin", func(t *testing.T) {
		u := newTestUserService()
		Superadmin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"),
			os.Getenv("CAKE_ADMIN_CAKE"), "superadmin", false, BanHistory{}}
		u.repository.Add(Superadmin.Email, Superadmin)
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_2 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_3 := httptest.NewServer(j.jwtAuthAdmin(u.repository, promoteHandler))
		ts_4 := httptest.NewServer(j.jwtAuthAdmin(u.repository, promoteHandler))
		ts_5 := httptest.NewServer(j.jwtAuthAdmin(u.repository, unbanHandler))

		defer ts_1.Close()
		defer ts_2.Close()
		defer ts_3.Close()
		defer ts_4.Close()
		defer ts_5.Close()

		reg1 := map[string]interface{}{
			"email":         "test1@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}

		reg2 := map[string]interface{}{
			"email":         "test2@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}

		promoteparams1 := map[string]interface{}{
			"email": "test1@mail.com",
		}

		promoteparams2 := map[string]interface{}{
			"email": "test2@mail.com",
		}

		unban := map[string]interface{}{
			"email": "test2@mail.com",
		}

		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, reg1)))
		doRequest(http.NewRequest(http.MethodPost, ts_2.URL, prepareParams(t, reg2)))

		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		admin, _ := u.repository.Get(os.Getenv("CAKE_ADMIN_EMAIL"))
		token, _ := jwtService.GenearateJWT(admin)

		req1, _ := http.NewRequest(http.MethodPost, ts_3.URL, prepareParams(t, promoteparams1))
		req1.Header.Add("Authorization", "Bearer "+string(token))
		doRequest(req1, err)

		user, _ := u.repository.Get("test1@mail.com")
		user_token, _ := jwtService.GenearateJWT(user)

		req2, _ := http.NewRequest(http.MethodPost, ts_4.URL, prepareParams(t, promoteparams2))
		req2.Header.Add("Authorization", "Bearer "+string(token))
		doRequest(req2, err)

		req, _ := http.NewRequest(http.MethodPost, ts_5.URL, prepareParams(t, unban))
		req.Header.Add("Authorization", "Bearer "+string(user_token))
		resp := doRequest(req, err)

		assertStatus(t, 401, resp)
		assertBody(t, "Only superadmin can unban admin!", resp)
	})

	t.Run("unban user", func(t *testing.T) {
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
		ts_3 := httptest.NewServer(j.jwtAuthAdmin(u.repository, unbanHandler))
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

		unbanparams := map[string]interface{}{
			"email": "test@mail.com",
		}

		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params)))

		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		admin, _ := u.repository.Get(os.Getenv("CAKE_ADMIN_EMAIL"))
		token, _ := jwtService.GenearateJWT(admin)

		request, _ := http.NewRequest(http.MethodPost, ts_2.URL, prepareParams(t, banparams))
		request.Header.Add("Authorization", "Bearer "+string(token))
		doRequest(request, err)

		req, _ := http.NewRequest(http.MethodPost, ts_3.URL, prepareParams(t, unbanparams))
		req.Header.Add("Authorization", "Bearer "+string(token))
		resp := doRequest(req, err)
		assertStatus(t, 201, resp)
		assertBody(t, "The user have been unbanned", resp)
	})

	t.Run("inspect user", func(t *testing.T) {
		u := newTestUserService()
		Superadmin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"),
			os.Getenv("CAKE_ADMIN_CAKE"), "superadmin", false, BanHistory{}}
		u.repository.Add(Superadmin.Email, Superadmin)
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_2 := httptest.NewServer(j.jwtAuthAdmin(u.repository, inspectHandler))
		defer ts_1.Close()
		defer ts_2.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}

		inspectparams := map[string]interface{}{
			"email": "test@mail.com",
		}

		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params)))

		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		admin, _ := u.repository.Get(os.Getenv("CAKE_ADMIN_EMAIL"))
		token, _ := jwtService.GenearateJWT(admin)

		req, _ := http.NewRequest(http.MethodGet, ts_2.URL, prepareParams(t, inspectparams))
		req.Header.Add("Authorization", "Bearer "+string(token))
		resp := doRequest(req, err)
		user, _ := u.repository.Get("test@mail.com")
		assertStatus(t, 200, resp)
		assertBody(t, "User : "+user.Email+"\n"+"Favorite cake : "+user.FavoriteCake+"\n"+"Banned : "+strconv.FormatBool(user.Banned)+"\n"+"Role : "+user.Role+"\n"+"Who banned : "+user.BanHistory.WhoBanned+"\n"+"When : "+user.BanHistory.WhenBanned.String()+"\n"+"Why : "+user.BanHistory.Why+"\n"+"Who unbanned : "+user.BanHistory.WhoUnbanned+"\n", resp)
	})

	t.Run("promote user", func(t *testing.T) {
		u := newTestUserService()
		Superadmin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"),
			os.Getenv("CAKE_ADMIN_CAKE"), "superadmin", false, BanHistory{}}
		u.repository.Add(Superadmin.Email, Superadmin)
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_2 := httptest.NewServer(j.jwtAuthAdmin(u.repository, promoteHandler))
		defer ts_1.Close()
		defer ts_2.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}

		promoteparams := map[string]interface{}{
			"email": "test@mail.com",
		}

		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params)))

		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		admin, _ := u.repository.Get(os.Getenv("CAKE_ADMIN_EMAIL"))
		token, _ := jwtService.GenearateJWT(admin)

		req, _ := http.NewRequest(http.MethodPost, ts_2.URL, prepareParams(t, promoteparams))
		req.Header.Add("Authorization", "Bearer "+string(token))
		resp := doRequest(req, err)
		assertStatus(t, 201, resp)
		assertBody(t, "The user have been promoted", resp)
	})

	t.Run("fire user", func(t *testing.T) {
		u := newTestUserService()
		Superadmin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"),
			os.Getenv("CAKE_ADMIN_CAKE"), "superadmin", false, BanHistory{}}
		u.repository.Add(Superadmin.Email, Superadmin)
		j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}
		ts_1 := httptest.NewServer(http.HandlerFunc(u.Register))
		ts_2 := httptest.NewServer(j.jwtAuthAdmin(u.repository, promoteHandler))
		ts_3 := httptest.NewServer(j.jwtAuthAdmin(u.repository, fireHandler))
		defer ts_1.Close()
		defer ts_2.Close()
		defer ts_3.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cake",
		}

		promoteparams := map[string]interface{}{
			"email": "test@mail.com",
		}

		fireteparams := map[string]interface{}{
			"email": "test@mail.com",
		}

		doRequest(http.NewRequest(http.MethodPost, ts_1.URL, prepareParams(t, params)))

		jwtService, err := NewJWTService("pubkey.rsa", "privkey.rsa")
		admin, _ := u.repository.Get(os.Getenv("CAKE_ADMIN_EMAIL"))
		token, _ := jwtService.GenearateJWT(admin)

		request, _ := http.NewRequest(http.MethodPost, ts_2.URL, prepareParams(t, promoteparams))
		request.Header.Add("Authorization", "Bearer "+string(token))
		doRequest(request, err)

		req, _ := http.NewRequest(http.MethodPost, ts_3.URL, prepareParams(t, fireteparams))
		req.Header.Add("Authorization", "Bearer "+string(token))
		resp := doRequest(req, err)
		assertStatus(t, 201, resp)
		assertBody(t, "The user have been fired", resp)
	})
}
