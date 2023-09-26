package DB

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

func Connect() (client *mongo.Client) {
	ctx := context.TODO()
	opts := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		panic(err)
	}
	if errr := client.Ping(ctx, readpref.Primary()); err != nil {
		panic(errr)
	}
	return client

}

func UserExist(UUID string) bool {
	ctx := context.TODO()
	client := Connect()
	result, _ := client.Database("auth").Collection("auth").Find(ctx, bson.D{{"UUID", UUID}})
	var results []bson.M
	result.All(ctx, &results)
	if len(results) > 0 {
		return true
	} else {
		return false
	}
}

func GetUUIDFromRT(RefreshToken string) (UUID string) {
	ctx := context.TODO()
	client := Connect()
	result, _ := client.Database("auth").Collection("auth").Find(ctx, bson.D{{"Refresh", hashing(RefreshToken)}})
	var results []bson.M
	result.All(ctx, &results)
	if len(results) > 0 {
		return fmt.Sprint(results[0]["UUID"])
	} else {
		return ""
	}
}

func hashing(input string) string {
	plainText := []byte(input)
	sha256Hash := sha256.Sum256(plainText)
	return hex.EncodeToString(sha256Hash[:])
}
