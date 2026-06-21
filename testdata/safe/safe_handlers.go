package safe

import "github.com/gin-gonic/gin"

func registerSafe(router *gin.Engine) {
	// Admin route WITH a role check → not BFLA.
	router.POST("/admin/users", requireRole("admin"), deleteUser)
	// Authenticated handler → not missing-auth.
	router.GET("/profile", requireAuth, getProfile)
}
