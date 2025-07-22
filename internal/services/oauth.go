package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/sharan-industries/identity-service/internal/config"
	"github.com/sharan-industries/identity-service/internal/models"
	"github.com/sharan-industries/identity-service/internal/repository"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

type OAuthService struct {
	cfg          *config.Config
	userRepo     *repository.UserRepository
	authService  *AuthService
	googleConfig *oauth2.Config
	githubConfig *oauth2.Config
	msConfig     *oauth2.Config
}

type OAuthUserInfo struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Picture  string `json:"picture,omitempty"`
	Provider string `json:"provider"`
}

func NewOAuthService(cfg *config.Config, userRepo *repository.UserRepository, authService *AuthService) *OAuthService {
	service := &OAuthService{
		cfg:         cfg,
		userRepo:    userRepo,
		authService: authService,
	}

	// Initialize Google OAuth config
	if cfg.GoogleClientID != "" {
		service.googleConfig = &oauth2.Config{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURL:  cfg.GoogleRedirectURL,
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     google.Endpoint,
		}
	}

	// Initialize GitHub OAuth config
	if cfg.GitHubClientID != "" {
		service.githubConfig = &oauth2.Config{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			RedirectURL:  cfg.GitHubRedirectURL,
			Scopes:       []string{"user:email"},
			Endpoint:     github.Endpoint,
		}
	}

	// Initialize Microsoft OAuth config
	if cfg.MicrosoftClientID != "" {
		service.msConfig = &oauth2.Config{
			ClientID:     cfg.MicrosoftClientID,
			ClientSecret: cfg.MicrosoftClientSecret,
			RedirectURL:  cfg.MicrosoftRedirectURL,
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     microsoft.AzureADEndpoint("common"),
		}
	}

	return service
}

// Google OAuth
func (s *OAuthService) GetGoogleAuthURL(state string) string {
	if s.googleConfig == nil {
		return ""
	}
	return s.googleConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (s *OAuthService) HandleGoogleCallback(ctx context.Context, code string) (*models.AuthTokens, *models.User, error) {
	if s.googleConfig == nil {
		return nil, nil, fmt.Errorf("Google OAuth not configured")
	}

	// Exchange code for token
	token, err := s.googleConfig.Exchange(ctx, code)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Get user info from Google
	userInfo, err := s.getGoogleUserInfo(ctx, token.AccessToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user info: %w", err)
	}

	return s.processOAuthUser(userInfo)
}

func (s *OAuthService) getGoogleUserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error) {
	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + accessToken)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var googleUser struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}

	if err := json.Unmarshal(body, &googleUser); err != nil {
		return nil, err
	}

	return &OAuthUserInfo{
		ID:       googleUser.ID,
		Email:    googleUser.Email,
		Name:     googleUser.Name,
		Picture:  googleUser.Picture,
		Provider: "google",
	}, nil
}

// GitHub OAuth
func (s *OAuthService) GetGitHubAuthURL(state string) string {
	if s.githubConfig == nil {
		return ""
	}
	return s.githubConfig.AuthCodeURL(state)
}

func (s *OAuthService) HandleGitHubCallback(ctx context.Context, code string) (*models.AuthTokens, *models.User, error) {
	if s.githubConfig == nil {
		return nil, nil, fmt.Errorf("GitHub OAuth not configured")
	}

	// Exchange code for token
	token, err := s.githubConfig.Exchange(ctx, code)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Get user info from GitHub
	userInfo, err := s.getGitHubUserInfo(ctx, token.AccessToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user info: %w", err)
	}

	return s.processOAuthUser(userInfo)
}

func (s *OAuthService) getGitHubUserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error) {
	// Get user profile
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "token "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var githubUser struct {
		ID     int    `json:"id"`
		Login  string `json:"login"`
		Name   string `json:"name"`
		Email  string `json:"email"`
		Avatar string `json:"avatar_url"`
	}

	if err := json.Unmarshal(body, &githubUser); err != nil {
		return nil, err
	}

	// If email is not public, get it from emails endpoint
	if githubUser.Email == "" {
		email, err := s.getGitHubPrimaryEmail(accessToken)
		if err == nil {
			githubUser.Email = email
		}
	}

	return &OAuthUserInfo{
		ID:       fmt.Sprintf("%d", githubUser.ID),
		Email:    githubUser.Email,
		Name:     githubUser.Name,
		Picture:  githubUser.Avatar,
		Provider: "github",
	}, nil
}

func (s *OAuthService) getGitHubPrimaryEmail(accessToken string) (string, error) {
	req, _ := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	req.Header.Set("Authorization", "token "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var emails []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}

	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}

	for _, email := range emails {
		if email.Primary {
			return email.Email, nil
		}
	}

	return "", fmt.Errorf("no primary email found")
}

// Microsoft OAuth
func (s *OAuthService) GetMicrosoftAuthURL(state string) string {
	if s.msConfig == nil {
		return ""
	}
	return s.msConfig.AuthCodeURL(state)
}

func (s *OAuthService) HandleMicrosoftCallback(ctx context.Context, code string) (*models.AuthTokens, *models.User, error) {
	if s.msConfig == nil {
		return nil, nil, fmt.Errorf("Microsoft OAuth not configured")
	}

	// Exchange code for token
	token, err := s.msConfig.Exchange(ctx, code)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Get user info from Microsoft Graph
	userInfo, err := s.getMicrosoftUserInfo(ctx, token.AccessToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user info: %w", err)
	}

	return s.processOAuthUser(userInfo)
}

func (s *OAuthService) getMicrosoftUserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error) {
	req, _ := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var msUser struct {
		ID          string `json:"id"`
		Mail        string `json:"mail"`
		DisplayName string `json:"displayName"`
		UserPrincipalName string `json:"userPrincipalName"`
	}

	if err := json.Unmarshal(body, &msUser); err != nil {
		return nil, err
	}

	email := msUser.Mail
	if email == "" {
		email = msUser.UserPrincipalName
	}

	return &OAuthUserInfo{
		ID:       msUser.ID,
		Email:    email,
		Name:     msUser.DisplayName,
		Provider: "microsoft",
	}, nil
}

// Common OAuth user processing
func (s *OAuthService) processOAuthUser(userInfo *OAuthUserInfo) (*models.AuthTokens, *models.User, error) {
	if userInfo.Email == "" {
		return nil, nil, fmt.Errorf("email not provided by OAuth provider")
	}

	// Check if user exists
	existingUser, err := s.userRepo.GetByEmail(userInfo.Email)
	if err == nil && existingUser != nil {
		// User exists - link OAuth account if not already linked
		err = s.linkOAuthAccount(existingUser, userInfo)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to link OAuth account: %w", err)
		}

		// Generate tokens for existing user
		tokens, err := s.authService.generateTokensForUser(existingUser)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate tokens: %w", err)
		}

		return tokens, existingUser, nil
	}

	// User doesn't exist - create new user
	newUser, err := s.createUserFromOAuth(userInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create user from OAuth: %w", err)
	}

	// Generate tokens for new user
	tokens, err := s.authService.generateTokensForUser(newUser)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return tokens, newUser, nil
}

func (s *OAuthService) createUserFromOAuth(userInfo *OAuthUserInfo) (*models.User, error) {
	// Parse name into first and last name
	nameParts := strings.Fields(userInfo.Name)
	firstName := ""
	lastName := ""
	
	if len(nameParts) > 0 {
		firstName = nameParts[0]
	}
	if len(nameParts) > 1 {
		lastName = strings.Join(nameParts[1:], " ")
	}

	user := &models.User{
		Email:       userInfo.Email,
		FirstName:   firstName,
		LastName:    lastName,
		IsEmailVerified: true, // OAuth emails are considered verified
		OAuthAccounts: []models.OAuthAccount{
			{
				Provider:   userInfo.Provider,
				ProviderID: userInfo.ID,
				Email:      userInfo.Email,
			},
		},
	}

	// Create user and assign default role
	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}

	// Assign default role
	if err := s.userRepo.AssignRoleByName(user.ID, "user"); err != nil {
		return nil, fmt.Errorf("failed to assign default role: %w", err)
	}

	// Reload user with relationships
	return s.userRepo.GetByID(user.ID)
}

func (s *OAuthService) linkOAuthAccount(user *models.User, userInfo *OAuthUserInfo) error {
	// Check if this OAuth account is already linked
	for _, account := range user.OAuthAccounts {
		if account.Provider == userInfo.Provider && account.ProviderID == userInfo.ID {
			// Already linked
			return nil
		}
	}

	// Create new OAuth account link
	oauthAccount := models.OAuthAccount{
		UserID:     user.ID,
		Provider:   userInfo.Provider,
		ProviderID: userInfo.ID,
		Email:      userInfo.Email,
	}

	return s.userRepo.CreateOAuthAccount(&oauthAccount)
}