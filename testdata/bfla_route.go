package testdata

import "github.com/gin-gonic/gin"

// Admin route with NO role/permission check and no auth in this file → BFLA.
func registerAdmin(router *gin.Engine) {
	router.POST("/admin/users", deleteUserHandler)
}
