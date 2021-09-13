package authorization

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"net/http"
	"strings"
	"time"
)

func Login(c *gin.Context) {

	var user *Users
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "incorrect parameters",
		})
		return
	}
	user, err = findUser(user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": fmt.Sprintf("Неправильный логин или пароль"),
		})
		return
	}
	fmt.Println(user)
	accessToken, err := generateAccessToken(*user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}
	refreshToken, err := generateRefreshToken(*user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}
	err = startSession(user.Id,refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"accessToken": accessToken,
		"refreshToken": refreshToken,
	})
}

func generateRefreshToken(user Users) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwtRefreshClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		},
		Id: user.Id,
	})
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}


func generateAccessToken(user Users) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwtAccessClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
		Email: user.Email,
		Id: user.Id,
	})
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func validateToken(tokenString string) (*Users, error) {
	var claims jwtAccessClaims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return &Users{
		Email: claims.Email,
		Id: claims.Id,
	}, nil
}
func VerifyAccessToken(c *gin.Context) {

	authValue := c.GetHeader("Authorization")
	arr := strings.Split(authValue, " ")
	//fmt.Println(arr,"arr")
	if len(arr) != 2 {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"хеадер pustoi":""})
		return
	}
	//authType := strings.Trim(arr[0], "\n\r\t")
	//fmt.Println(authType,"authtype")
	//if strings.ToLower(authType) != strings.ToLower("Bearer") {
	//	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{})
	//	return
	//}
	token := arr[1]
	//fmt.Println(token,"token")
	user, err := validateToken(token)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"Ошибка": err.Error()})
		return
	}
	if user.Email  == "" || user.Id == 0 {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"рефреш токен не авторизирует": ""})
		return
	}
	c.Set("id", user.Id)
	c.Set("email", user.Email)
	//c.Writer.Header().Set("Authorization", "Bearer "+token)
	fmt.Println(c.Keys["email"])
	c.Next()
}

func ValidateRefreshToken(c *gin.Context) {
	var RefreshPar struct {
		RefreshToken string `pg:"refresh_token"`
	}
	err := c.Bind(&RefreshPar)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	fmt.Println(RefreshPar)
	user, err := findSession(RefreshPar.RefreshToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	accessToken, err := generateAccessToken(*user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"accessToken": accessToken,
		"refreshToken": RefreshPar.RefreshToken,
	})
}

func RegisterUser(c *gin.Context) {
	var user *Users
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "incorrect parameters",
		})
		return
	}
	user, err = createUser(user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Ошибка при регистрации"),
		})
		return
	}
	err = SmtpTest(user.Email)
	if err != nil {
		fmt.Println(err.Error())
	}
		c.JSON(http.StatusOK, gin.H{
			user.Email: "зарегистрирован",
		})
}

func ForgotPassword (c *gin.Context){
	var user *Users
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "incorrect parameters",
		})
		return
	}
	user, err = findEmail(user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": fmt.Sprintf("Такого мыла не существует"),
		})
		return
	}
	recoveryToken, err := generateAccessToken(*user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"recoveryToken": recoveryToken,
	})
}

func SetNewPassword (c *gin.Context) {


	recoveryToken := c.Query("token")

	var Params struct {
		Password string
	}
	err := c.Bind(&Params)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	user, err := validateToken(recoveryToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
	}
	fmt.Println(user,Params.Password)
	user.Password = Params.Password
	err = changePassword(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
	}
	c.JSON(http.StatusOK, gin.H{
		user.Email: "Пароль изменен успешно",
	})

}