package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sharan-industries/identity-service/internal/services"
)

type ValidateHandler struct {
	jwtService *services.JWTService
}

func NewValidateHandler(jwtService *services.JWTService) *ValidateHandler {
	return &ValidateHandler{
		jwtService: jwtService,
	}
}

type ValidateTokenRequest struct {
	Token string `json:"token" binding:"required"`
}

type ValidateTokenResponse struct {
	Valid  bool                  `json:"valid"`
	Claims *services.Claims      `json:"claims,omitempty"`
	Error  string                `json:"error,omitempty"`
}

// ValidateToken validates a JWT token and returns claims
func (h *ValidateHandler) ValidateToken(c *gin.Context) {
	var req ValidateTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ValidateTokenResponse{
			Valid: false,
			Error: err.Error(),
		})
		return
	}

	// Validate the token
	claims, err := h.jwtService.ValidateAccessToken(req.Token)
	if err != nil {
		c.JSON(http.StatusOK, ValidateTokenResponse{
			Valid: false,
			Error: err.Error(),
		})
		return
	}

	// Return valid response with claims
	c.JSON(http.StatusOK, ValidateTokenResponse{
		Valid:  true,
		Claims: claims,
	})
}