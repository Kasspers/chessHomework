package authorization

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-pg/pg"
	"net/http"
)

var DB *pg.DB

func findUser(user *Users) (*Users, error) {
	_, err := DB.QueryOne(user, `SELECT id, email, password FROM users WHERE email = ? AND password = ?`, user.Email,user.Password)
	if err != nil {
		fmt.Println("finduser err",err)
		return nil, err
	}
	fmt.Println(user)
	return user, nil
}
func findEmail(user *Users) (*Users, error) {
	_, err := DB.QueryOne(user, `SELECT email FROM users WHERE email = ?`, user.Email)
	if err != nil {
		fmt.Println("findEmail err",err)
		return nil, err
	}
	fmt.Println(user)
	return user, nil
}


func startSession (id int64, token string) error {
	_, err := DB.Exec(`INSERT INTO sessions (user_id, refresh_token) values (?,?)`, id,token)
	if err != nil {
		return err
	}
	return nil
}

func findSession(refreshToken string) (*Users, error) {
	var user Users
	_, err := DB.QueryOne(&user, `SELECT id, email FROM users INNER JOIN sessions s on s.user_id = user_roles.user_id WHERE refresh_token = ?`, refreshToken)
	if err != nil {
		fmt.Println("finduser err",err)
		return nil, err
	}
	fmt.Println(user)
	return &user, nil
}

func Logout(c *gin.Context) {
	var id string
	fmt.Println(c.Keys["id"])
	_, err := DB.QueryOne(&id, `DELETE FROM sessions WHERE user_id = ? RETURNING user_id`, c.Keys["id"])
	if err == nil {
		c.JSON(http.StatusOK, gin.H{
			id : "удален",
		})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{
		"error msg": err.Error(),
	})
}

func createUser(user *Users) (*Users, error){

	_, err := DB.QueryOne(user, `
		INSERT INTO users (email, password) VALUES (?email, ?password) RETURNING *`, user)
	if err != nil {
		fmt.Println("create user err",err)
		return nil, err
	}
	fmt.Println(user)
	return user, nil
}

func changePassword (user *Users) error {
	_, err := DB.QueryOne(user, `UPDATE users SET password = (?) WHERE email = (?) RETURNING email`, user.Password,user.Email)
	if err != nil {
		fmt.Println("change password err", err)
		return err
	}
	return nil
}

