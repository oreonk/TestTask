package Auth

import (
	"github.com/golang-jwt/jwt/v5"
	"os"
	"time"
)

// GetSecret Вытащить секрет с файла
func GetSecret() string {
	//Ключ желательно закодировать...
	b, err := os.ReadFile("User/Auth/JS")
	if err != nil {
		panic(err)
	}
	str := string(b)
	return str
}

func CreateToken(uuid string) (tokenString string, err error) {
	var (
		secret []byte
		token  *jwt.Token
	)
	secret = []byte(GetSecret())
	expired := time.Now().Add(15 * time.Minute)
	token = jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": uuid,
		"exp": expired.Unix(),
	})
	tokenString, err = token.SignedString(secret)
	if err != nil {
		panic(err)
	}
	return
}

// ValidateToken проверяет токен, возвращает ошибку в виде стринга (если нет - пустой стринг)
// Ошибки: jwt.err.expired - действие токена закончилось, jwt.err.parse - ошибка при парсинге токена, jwt.err.invalid - все остальное
func ValidateToken(signedToken string) string {
	token, jwterror := jwt.ParseWithClaims(
		signedToken,
		jwt.MapClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(GetSecret()), nil
		},
	)
	if token.Claims != nil {
		claimsTime, parseerror := token.Claims.(jwt.MapClaims).GetExpirationTime()

		if parseerror != nil {
			return "jwt.err.parse"
		}
		if claimsTime.Unix() < time.Now().Unix() {
			return "jwt.err.expired"
		}
		if jwterror != nil {
			return "jwt.err.invalid"
		}
		return ""
	} else {
		return "jwt.err.invalid"
	}
}

func ParseUserUUID(signedToken string) string {
	token, _ := jwt.ParseWithClaims(
		signedToken,
		jwt.MapClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(GetSecret()), nil
		},
	)
	claimsUUID, parseerror := token.Claims.(jwt.MapClaims).GetSubject()
	if parseerror != nil {
		panic(parseerror)
	}
	return claimsUUID
}
