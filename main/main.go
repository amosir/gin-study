package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	// 创建一个 gin Engine，本质上是一个 http Handler
	mux := gin.Default()
	// 注册一个 path 为 /ping 的处理函数
	mux.POST("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, "pone")
	})

	err := mux.Run("0.0.0.0:8080")
	if err != nil {
		panic(err)
	}
}
