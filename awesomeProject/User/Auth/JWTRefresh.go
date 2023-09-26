package Auth

import (
	"awesomeProject/User/Auth/DB"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"math/rand"
	"strconv"
	"time"
)

// CreateRefreshToken генерирует новый рандомный рефреш токен
func CreateRefreshToken() string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!*")

	rand.New(rand.NewSource(time.Now().Unix()))
	b := make([]rune, 32)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func ValidateRTToken(UUID string, RefreshToken string) string {
	encodedtoken := Hashing(RefreshToken)
	ctx := context.TODO()
	client := DB.Connect()
	result, err := client.Database("auth").Collection("auth").Find(ctx,
		bson.D{
			{"$and",
				bson.A{
					bson.D{{"UUID", UUID}},
					bson.D{{"Refresh", encodedtoken}},
				}},
		})
	if err != nil {
		panic(err)
	}
	defer client.Disconnect(ctx)
	var results []bson.M
	errr := result.All(ctx, &results)
	if results == nil {
		return "rt.err.invalid"
	}
	var timer = results[0]["RefreshValid"]
	timerr, _ := strconv.ParseInt(fmt.Sprint(timer), 10, 64)
	if timerr < time.Now().Unix() {
		return "rt.err.expired"
	}
	if errr != nil {
		panic(errr)
		return "rt.err.invalid"
	}
	return ""
}

// Hashing sha256 hash
func Hashing(input string) string {
	plainText := []byte(input)
	sha256Hash := sha256.Sum256(plainText)
	return hex.EncodeToString(sha256Hash[:])
}

// ChangeRT изменение/создание рефреш токена у юзера в БД
// Бросает db.err.changert в том случае, если рефреш токен не изменился. Если ошибки нет - возвращает пустую строку
func ChangeRT(UUID string, RefreshToken string) (error string) {
	ctx := context.TODO()
	client := DB.Connect()
	ecnodedtoken := Hashing(RefreshToken)
	result, err := client.Database("auth").Collection("auth").UpdateOne(ctx,
		bson.M{"UUID": UUID},
		bson.D{
			{"$set", bson.D{{"Refresh", ecnodedtoken}}},
		},
	)
	if err != nil {
		panic(err)
	}
	//Месяц
	expired := time.Now().Add(730 * time.Hour)
	//Костыль
	result1, err1 := client.Database("auth").Collection("auth").UpdateOne(ctx,
		bson.M{"UUID": UUID},
		bson.D{
			{"$set", bson.D{{"RefreshValid", expired.Unix()}}},
		},
	)
	if err1 != nil {
		panic(err1)
		return "db.err.changert"
	}
	defer client.Disconnect(ctx)
	if result.ModifiedCount == 0 || result1.ModifiedCount == 0 {
		return "db.err.changert"
	} else {
		return ""
	}
}

// hashing sha256 hash
