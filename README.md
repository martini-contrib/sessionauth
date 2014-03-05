# sessionauth [![wercker status](https://app.wercker.com/status/2ca96622162f80499f954e2c8a2e44a1 "wercker status")](https://app.wercker.com/project/bykey/2ca96622162f80499f954e2c8a2e44a1)

## Purpose

This package provides a simple way to make routes require a login, and to handle user logins in
the session. It should work with any user model that you have in your application, so long as
your user model implements the login.User interface.

Please see the example program in the example/ directory.

## Program Flow:

Every new request to Martini will generate an Anonymous login.User struct using the function passed
to SessionUser. This should default to a zero value user model, and must implement the login.User
interface. If a user exists in the request session, this user will be injected into every request 
handler. Otherwise the zero value object will be injected.

When a user visits any route with the **LoginRequired** handler, the login.User object will be
examined with the IsAuthenticated() function. If the user is not authenticated, they will be
redirected to a login page (/login).

To log your users in, you should create a POST route, and verify the user/password that was sent
from the client. Due to the vast possibilities of doing this, you must be responsible for
validating a user. Once that user is validated, call login.AuthenticateSession() to mark the
session as authenticated.

Your user type should meet the login.User interface:

```go
    type User interface {
        // Return whether this user is logged in or not
        IsAuthenticated() bool

        // Set any flags or extra data that should be available
        Login()

        // Clear any sensitive data out of the user
        Logout()

        // Return the unique identifier of this user object
        UniqueID() interface{}

        // Populate this user object with values
        GetByID(id interface{}) error
   }
```

The SessionUser() Martini middleware will inject the login.User interface
into your route handlers. These interfaces must be converted to your
appropriate type to function correctly.

```go
    func handler(user login.User, db *MyDB) {
        u := user.(*UserModel)
        db.Save(u)
    }
```
