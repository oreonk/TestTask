package main

import (
	"awesomeProject/User/Auth"
	"awesomeProject/User/Auth/DB"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

// Далее - этим middleware можно покрыть эндпоинты, которые необходимо защитить с помощью JWT
func jwtMiddleware() gin.HandlerFunc {
	return func(context *gin.Context) {
		jwtString := context.GetHeader("JWT")
		if jwtString == "" {
			context.JSON(401, gin.H{"error": "Not authorized"})
			context.Abort()
			return
		}
		jwtValidateError := Auth.ValidateToken(jwtString)
		if jwtValidateError == "jwt.err.expired" {
			context.JSON(401, gin.H{"error": "JWT token expired"})
			context.Abort()
			return
		}
		if jwtValidateError == "jwt.err.parse" {
			context.JSON(401, gin.H{"error": "JWT parse error"})
			context.Abort()
			return
		}
		if jwtValidateError == "jwt.err.invalid" {
			context.JSON(401, gin.H{"error": "Invalid JWT"})
			context.Abort()
			return
		}
		context.Next()
	}
}
func rtMiddleware() gin.HandlerFunc {
	return func(context *gin.Context) {
		rtString := context.GetHeader("Refresh")
		if rtString == "" {
			context.JSON(401, gin.H{"error": "Not authorized"})
			context.Abort()
			return
		}
		if len(rtString) != 32 {
			context.JSON(401, gin.H{"error": "Invalid refresh token"})
			context.Abort()
			return
		}
		rtValidateError := Auth.ValidateRTToken(DB.GetUUIDFromRT(rtString), rtString)
		if rtValidateError == "rt.err.expired" {
			context.JSON(401, gin.H{"error": "Refresh token expired"})
			context.Abort()
			return
		}
		if rtValidateError == "rt.err.invalid" {
			context.JSON(401, gin.H{"error": "Invalid refresh token"})
			context.Abort()
			return
		}
		context.Next()
	}
}

type TokenRequest struct {
	UUID string `json:"UUID"`
}

// Todo():
// Добавить проверку логина и пароля
func createTokens(context *gin.Context) {
	var request TokenRequest
	if err := context.ShouldBindJSON(&request); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		context.Abort()
		return
	}
	UUID := request.UUID
	if DB.UserExist(UUID) {
		jwt, err := Auth.CreateToken(UUID)
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			context.Abort()
			return
		}
		refreshToken := Auth.CreateRefreshToken()
		err1 := Auth.ChangeRT(UUID, refreshToken)
		if err1 != "" {
			context.JSON(http.StatusInternalServerError, gin.H{"error": "Error while handling database"})
			context.Abort()
			return
		}
		context.JSON(http.StatusOK, gin.H{"JWT": jwt, "Refresh": refreshToken})
		fmt.Print(jwt)
	} else {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "No User with this UUID"})
		context.Abort()
		return
	}
}

func refreshTokens(context *gin.Context) {
	refresh := context.GetHeader("Refresh")
	if DB.GetUUIDFromRT(refresh) != "" {
		UUID := DB.GetUUIDFromRT(refresh)
		if DB.UserExist(UUID) {
			jwt, err := Auth.CreateToken(UUID)
			if err != nil {
				context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				context.Abort()
				return
			}
			refreshToken := Auth.CreateRefreshToken()
			err1 := Auth.ChangeRT(UUID, refreshToken)
			if err1 != "" {
				context.JSON(http.StatusInternalServerError, gin.H{"error": "Error while handling database"})
				context.Abort()
				return
			}
			context.JSON(http.StatusOK, gin.H{"JWT": jwt, "Refresh": refreshToken})
			fmt.Print(jwt)
		} else {
			context.JSON(http.StatusInternalServerError, gin.H{"error": "No User with this UUID"})
			context.Abort()
			return
		}
	}
}
func main() {
	//3oQshK9cB25ujGBi_Sm5Fnu6mCS7JsGQ refresh
	//fmt.Print(DB.UserExist("1asd1fh"))
	//fmt.Println(Auth.ValidateRTToken("1asd1", "3oQshK9cB25ujGBi_Sm5Fnu6mCS7JsGQ"))
	router := initRouter()
	router.Run(":8080")
}
func initRouter() *gin.Engine {
	router := gin.Default()
	api := router.Group("/api")
	{
		api.POST("/JWT", createTokens)
		secured := api.Group("/secured").Use(rtMiddleware())
		secured.GET("/refresh", refreshTokens)
	}
	return router
}
