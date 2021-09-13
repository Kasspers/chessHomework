package main

import (
	"chess/authorization"
	"chess/websocket"
	"github.com/gin-gonic/gin"
	"github.com/go-pg/pg"
)

//var db *pg.DB

func main() {

	hub := websocket.NewHub()
	go hub.Run()

	authorization.DB = pg.Connect(&pg.Options{
		User:     "postgres",
		Password: "12345",
		Database: "chess_game",
	})
	defer authorization.DB.Close()

	r := gin.Default()

	r.LoadHTMLFiles("home.html")
	r.POST("password-recovery", authorization.ForgotPassword)
	r.POST("registration", authorization.RegisterUser)
	r.POST("refresh", authorization.ValidateRefreshToken)
	r.POST("login", authorization.Login)
	r.POST("set-new-password", authorization.SetNewPassword)
	//
	//r.GET("/ws", func(c *gin.Context) {
	//	websocket.ServeWs(hub,c.Writer, c.Request)
	//})
	//
	//r.Use(authorization.VerifyAccessToken)
	//
	//r.GET("/", func(c *gin.Context) {
	//	c.HTML(200, "home.html", nil)
	//})

	r.GET("logout", authorization.Logout)

	r.Run()

}
