# Identity Backend

A production-ready centralized authentication and user management service built with Go and Gin framework. This service provides Single Sign-On (SSO) capabilities across multiple company products with comprehensive scope-based authorization.

## Features

- **JWT Authentication**: Secure token-based authentication with automatic refresh token rotation
- **Scope-Based Authorization**: Fine-grained permissions with OAuth-style scopes (`users:read`, `products:write`)
- **Role-Based Access Control**: User roles (user, moderator, admin) with inherited permissions
- **User Management**: Complete user profile and account management
- **OAuth Integration**: Complete Google, GitHub, and Microsoft Sign-In with account linking
- **Security**: Rate limiting, CORS, bcrypt password hashing, input validation
- **Database**: PostgreSQL with GORM ORM and automatic migrations

## Quick Start

### Prerequisites

- Go 1.21 or later
- PostgreSQL 15 or later
- Docker and Docker Compose (for containerized setup)

### Local Development Setup

1. **Clone and navigate to the project:**
   ```bash
   cd identity-service
   ```

2. **Install Go dependencies:**
   ```bash
   go mod tidy
   ```

3. **Copy and configure environment:**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` file with your configuration:
   ```env
   DATABASE_URL=postgres://username:password@localhost:5432/identity_service?sslmode=disable
   JWT_SECRET=your-super-secret-jwt-key-change-in-production
   PORT=8080
   ENVIRONMENT=development
   ```

4. **Start PostgreSQL database:**
   ```bash
   docker-compose up postgres -d
   ```

5. **Run the service locally:**
   ```bash
   go run cmd/server/main.go
   ```

6. **Verify the service is running:**
   ```bash
   curl http://localhost:8080/health
   # Should return: {"status":"healthy"}
   ```

The service will automatically:
- Connect to PostgreSQL
- Run database migrations
- Seed default roles and permissions
- Start the HTTP server on port 8080

### Docker Setup

Run the entire stack with Docker Compose:

```bash
docker-compose up -d
```

This will start both PostgreSQL and the identity service.

## API Endpoints

### Authentication

- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/logout` - User logout

### OAuth

- `GET /api/v1/auth/oauth/google` - Initiate Google OAuth
- `GET /api/v1/auth/oauth/google/callback` - Google OAuth callback
- `GET /api/v1/auth/oauth/github` - Initiate GitHub OAuth
- `GET /api/v1/auth/oauth/github/callback` - GitHub OAuth callback
- `GET /api/v1/auth/oauth/microsoft` - Initiate Microsoft OAuth
- `GET /api/v1/auth/oauth/microsoft/callback` - Microsoft OAuth callback

### User Management (Protected)

- `GET /api/v1/users/profile` - Get user profile
- `PUT /api/v1/users/profile` - Update user profile
- `DELETE /api/v1/users/account` - Delete user account

### Health Check

- `GET /health` - Service health check

## Development Commands

### Local Development
```bash
# Install dependencies
go mod tidy

# Run the application locally (requires PostgreSQL)
go run cmd/server/main.go

# Run tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/services -v

# Format code
go fmt ./...

# Lint code (requires golangci-lint)
golangci-lint run

# Build binary
go build -o bin/identity-service cmd/server/main.go
```

### Docker Commands
```bash
# Start full stack (PostgreSQL + Identity Service)
docker-compose up -d

# Start only PostgreSQL for local development
docker-compose up postgres -d

# View service logs
docker-compose logs -f identity-service

# Stop all services
docker-compose down

# Reset database (removes all data)
docker-compose down -v
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8080` |
| `ENVIRONMENT` | Runtime environment | `development` |
| `JWT_SECRET` | JWT signing secret | `default-secret-change-me` |
| `JWT_EXPIRY` | JWT token expiry | `1h` |
| `DATABASE_URL` | PostgreSQL connection string | `postgres://...` |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | - |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | - |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID | - |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth client secret | - |
| `MICROSOFT_CLIENT_ID` | Microsoft OAuth client ID | - |
| `MICROSOFT_CLIENT_SECRET` | Microsoft OAuth client secret | - |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | Rate limit threshold | `60` |

## Authorization Examples

### Scope-Based Middleware
```go
// Require specific scopes
users.GET("/admin", middleware.RequireScope("users:admin"))

// Require any of multiple permissions
products.POST("/", middleware.RequirePermission("products:write", "products:admin"))

// Require specific role
admin.GET("/dashboard", middleware.RequireRole("admin", "moderator"))
```

### JWT Token Structure
```json
{
  "user_id": 123,
  "email": "user@example.com",
  "roles": ["user"],
  "permissions": ["users:read", "products:read", "orders:read"],
  "scopes": ["users:read", "products:read", "orders:read"]
}
```

### Default Roles
- **user**: `users:read`, `products:read`, `orders:read`
- **moderator**: Above + write permissions
- **admin**: All permissions including admin scopes

## Architecture

The service follows a clean architecture pattern:

```
identity-service/
├── cmd/server/           # Application entry point (main.go)
├── internal/
│   ├── config/          # Configuration management
│   ├── handlers/        # HTTP request handlers (auth, user)
│   ├── middleware/      # Auth, CORS, rate limiting, scope validation
│   ├── models/          # Database models (User, Role, Permission)
│   ├── services/        # Business logic (AuthService, JWTService)
│   └── repository/      # Data access layer (UserRepo, TokenRepo)
├── pkg/
│   ├── database/        # Database connection, migration, seeding
│   └── utils/           # Shared utilities
```

## Security Features

- **JWT tokens** with automatic refresh token rotation
- **bcrypt password hashing** with salt rounds
- **Rate limiting** (60 requests/minute per IP)
- **CORS configuration** with origin validation
- **Input validation** with Gin binding
- **SQL injection protection** via GORM parameterized queries
- **Token expiration** and secure storage

## Testing the API

### User Registration
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "securepassword123",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

### User Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "securepassword123"
  }'
```

### Protected Route (requires JWT token)
```bash
curl -X GET http://localhost:8080/api/v1/users/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Integration with Other Services

### Validating JWT Tokens
```go
// In your other Go services
claims, err := jwtService.ValidateAccessToken(tokenString)
if err != nil {
    // Handle invalid token
}

// Check user permissions
if claims.HasScope("products:write") {
    // User can write products
}
```

### Database Seeding
The service automatically creates:
- **Default roles**: user, moderator, admin
- **Resource permissions**: users:read, products:write, orders:admin, etc.
- **New users** automatically get the "user" role

## Contributing

1. Follow Go conventions and best practices
2. Run tests before committing: `go test ./...`
3. Format code: `go fmt ./...`
4. Use meaningful commit messages
5. Ensure all new endpoints have proper authorization middleware

## OAuth Authentication

Complete OAuth integration with automatic account linking:

### ✅ **Supported Providers**
- **Google OAuth**: Full profile access with email verification
- **GitHub OAuth**: Public and private email access
- **Microsoft OAuth**: Microsoft Graph API integration

### 🔄 **OAuth Flow**
1. **Initiate**: Call `GET /api/v1/auth/oauth/{provider}` to get authorization URL
2. **Redirect**: User authorizes on provider's site
3. **Callback**: Provider redirects to callback endpoint
4. **Link/Create**: Automatically links to existing users or creates new accounts
5. **Login**: Returns same JWT tokens as traditional authentication

### 🔧 **Setup OAuth Providers**
```bash
# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URL=https://yourdomain.com/api/v1/auth/oauth/google/callback

# GitHub OAuth
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_REDIRECT_URL=https://yourdomain.com/api/v1/auth/oauth/github/callback

# Microsoft OAuth
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
MICROSOFT_REDIRECT_URL=https://yourdomain.com/api/v1/auth/oauth/microsoft/callback
```

### 🔒 **OAuth Security Features**
- **CSRF Protection**: State parameter validation
- **Account Linking**: Same email automatically links accounts
- **Email Verification**: OAuth emails considered verified
- **Consistent Permissions**: OAuth users get same role-based access

## Cross-Domain Support

This service is designed to work across multiple domains and subdomains:

### ✅ **Supported Architectures**
- **Same domain**: `mycompany.com/api`, `mycompany.com/app`
- **Subdomains**: `app.mycompany.com`, `admin.mycompany.com`, `api.mycompany.com`
- **Different domains**: `mycompany.com`, `myotherapp.com` (with proper CORS)

### 🔧 **Configuration for Cross-Domain**
```bash
# .env configuration
ALLOWED_ORIGINS=https://mycompany.com,https://app.mycompany.com,https://admin.mycompany.com
COOKIE_DOMAIN=.mycompany.com
CORS_ALLOWED_ORIGINS=https://mycompany.com,https://app.mycompany.com
```

### 📚 **Integration Examples**
- **Go services**: Use the provided `pkg/auth` client library
- **Node.js/Python**: Make HTTP requests to `/api/v1/auth/validate`
- **Frontend**: Include JWT tokens in Authorization headers

See [CROSS_DOMAIN_SETUP.md](./CROSS_DOMAIN_SETUP.md) for detailed integration guide.

## Status

✅ **Production Ready** - This identity service is fully functional with:

- [x] Complete authentication logic (register, login, JWT generation)
- [x] User management with profile operations
- [x] Scope-based authorization system
- [x] Role and permission management
- [x] JWT service with refresh token rotation
- [x] Repository layer for all database operations
- [x] Security middleware and rate limiting
- [x] Database migrations and seeding
- [x] OAuth provider integrations (Google, GitHub, Microsoft)
- [ ] Comprehensive test coverage
- [ ] OpenAPI documentation
