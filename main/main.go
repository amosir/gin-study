package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	mux := gin.Default()
	mux.Use(gin.Recovery())
	mux.GET("/time", func(c *gin.Context) {
		m := map[string]string{
			"time": time.Now().Format("2006-01-02"),
		}
		c.JSON(http.StatusOK, m)
	})
	err := mux.Run("0.0.0.0:8080")
	if err != nil {
		panic(err)
	}
}
