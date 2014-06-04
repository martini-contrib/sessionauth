// Auth example is an example application which requires a login
// to view a private link. The username is "testuser" and the password
// is "password". This will require GORP and an SQLite3 database.
package main

import (
	"database/sql"
	"github.com/martini-contrib/sessionauth"
	"github.com/martini-contrib/sessionauth/example/model"
	"github.com/coopernurse/gorp"
	"github.com/go-martini/martini"
	"github.com/martini-contrib/binding"
	"github.com/martini-contrib/render"
	"github.com/martini-contrib/sessions"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
	"os"
)

var dbmap *gorp.DbMap

func initDb() *gorp.DbMap {
	// Delete our SQLite database if it already exists so we have a clean start
	_, err := os.Open("martini-sessionauth.bin")
	if err == nil {
		os.Remove("martini-sessionauth.bin")
	}

	db, err := sql.Open("sqlite3", "martini-sessionauth.bin")
	if err != nil {
		log.Fatalln("Fail to create database", err)
	}

	dbmap := &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}
	dbmap.AddTableWithName(model.MyUserModel{}, "users").SetKeys(true, "Id")
	err = dbmap.CreateTablesIfNotExists()
	if err != nil {
		log.Fatalln("Could not build tables", err)
	}

	user := model.MyUserModel{Id: 1, Username: "testuser", Password: "password"}
	err = dbmap.Insert(&user)
	if err != nil {
		log.Fatalln("Could not insert test user", err)
	}
	return dbmap
}

func main() {
	store := sessions.NewCookieStore([]byte("secret123"))
	dbmap = initDb()

	m := martini.Classic()
	m.Use(render.Renderer())

	// Default our store to use Session cookies, so we don't leave logged in
	// users roaming around
	store.Options(sessions.Options{
		MaxAge: 0,
	})
	m.Use(sessions.Sessions("my_session", store))
	m.Use(sessionauth.SessionUser(model.GenerateAnonymousUser, generateUserRetriever(dbmap)))
	sessionauth.RedirectUrl = "/new-login"
	sessionauth.RedirectParam = "new-next"

	m.Get("/", func(r render.Render) {
		r.HTML(200, "index", nil)
	})

	m.Get("/new-login", func(r render.Render) {
		r.HTML(200, "login", nil)
	})

	m.Post("/new-login", binding.Bind(model.MyUserModel{}), func(session sessions.Session, postedUser model.MyUserModel, r render.Render, req *http.Request) {
		// You should verify credentials against a database or some other mechanism at this point.
		// Then you can authenticate this session.
		user := model.MyUserModel{}
		err := dbmap.SelectOne(&user, "SELECT * FROM users WHERE username = $1 and password = $2", postedUser.Username, postedUser.Password)
		if err != nil {
			r.Redirect(sessionauth.RedirectUrl)
			return
		} else {
			err := sessionauth.AuthenticateSession(session, &user)
			if err != nil {
				r.JSON(500, err)
			}

			params := req.URL.Query()
			redirect := params.Get(sessionauth.RedirectParam)
			r.Redirect(redirect)
			return
		}
	})

	m.Get("/private", sessionauth.LoginRequired, func(r render.Render, user sessionauth.User) {
		r.HTML(200, "private", user.(*model.MyUserModel))
	})

	m.Get("/logout", sessionauth.LoginRequired, func(session sessions.Session, user sessionauth.User, r render.Render) {
		sessionauth.Logout(session, user)
		r.Redirect("/")
	})

	m.Run()
}

func generateUserRetriever(dbmap *gorp.DbMap) sessionauth.UserRetriever {
	return func(id interface{}, user *sessionauth.User) error {
		err := dbmap.SelectOne(user, "SELECT * FROM users WHERE id = $1", id)
		if err != nil {
			log.Println("select one:", err)
			return err
		}

		return nil
	}
}
