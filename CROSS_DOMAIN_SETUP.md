# Cross-Domain Authentication Setup

This guide explains how to configure the identity service for cross-domain authentication across your subdomains (e.g., `mycompany.com`, `app.mycompany.com`, `admin.mycompany.com`).

## 🎯 **Cross-Domain Authentication Methods**

### Method 1: JWT Header-Based (Recommended)
Each service validates JWT tokens via HTTP headers. This is the most secure and flexible approach.

### Method 2: Shared Cookies (Optional Enhancement)
Cookies can be shared across subdomains for seamless user experience.

## ⚙️ **Configuration for Cross-Domain**

### 1. Environment Variables (.env)

```bash
# Cross-domain configuration
ALLOWED_ORIGINS=https://mycompany.com,https://app.mycompany.com,https://admin.mycompany.com
COOKIE_DOMAIN=.mycompany.com

# CORS origins
CORS_ALLOWED_ORIGINS=https://mycompany.com,https://app.mycompany.com,https://admin.mycompany.com

# JWT settings
JWT_SECRET=your-super-secret-production-key
JWT_EXPIRY=1h
REFRESH_TOKEN_EXPIRY=168h
```

### 2. DNS/Domain Setup

Your domains should be configured as:
```
identity-service.mycompany.com  → Identity Service (Port 8080)
app.mycompany.com              → Your App Service  
admin.mycompany.com            → Your Admin Service
api.mycompany.com              → Your API Service
```

## 🔧 **Integration with Other Services**

### Option A: Using the Go Client Library

```go
package main

import (
    "net/http"
    "github.com/sharan-industries/identity-service/pkg/auth"
)

func main() {
    // Create identity service client
    authClient := auth.NewClient("https://identity-service.mycompany.com")
    
    // Create protected handler
    protectedHandler := authClient.Middleware("users:read")(yourHandler)
    
    // Setup routes
    http.Handle("/api/users", protectedHandler)
    http.ListenAndServe(":8081", nil)
}

func yourHandler(w http.ResponseWriter, r *http.Request) {
    // Get user claims from context
    claims, ok := auth.UserClaimsFromContext(r.Context())
    if !ok {
        http.Error(w, "No user claims found", http.StatusInternalServerError)
        return
    }
    
    // Use user information
    userID := claims.UserID
    email := claims.Email
    hasAdminScope := claims.HasScope("users:admin")
    
    // Your business logic here...
}
```

### Option B: Manual JWT Validation

```go
func validateToken(tokenString string) (*UserClaims, error) {
    resp, err := http.Post(
        "https://identity-service.mycompany.com/api/v1/auth/validate",
        "application/json",
        bytes.NewBufferString(`{"token":"`+tokenString+`"}`),
    )
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result ValidateResponse
    json.NewDecoder(resp.Body).Decode(&result)
    
    if !result.Valid {
        return nil, errors.New(result.Error)
    }
    
    return result.Claims, nil
}
```

## 🌐 **Frontend Integration**

### JavaScript/TypeScript Example with Redirect Support

```typescript
class AuthService {
    private baseURL = 'https://identity-service.mycompany.com/api/v1';
    
    async login(email: string, password: string, redirectURL?: string) {
        const body: any = { email, password };
        
        // Include redirect URL if provided
        if (redirectURL) {
            body.redirect_url = redirectURL;
        }
        
        const response = await fetch(`${this.baseURL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        
        const data = await response.json();
        
        if (data.tokens) {
            // Store tokens for cross-domain use
            localStorage.setItem('access_token', data.tokens.access_token);
            localStorage.setItem('refresh_token', data.tokens.refresh_token);
            
            // Handle redirect URL from response
            if (data.redirect_url) {
                window.location.href = data.redirect_url;
                return;
            }
        }
        
        return data;
    }
    
    async makeAuthenticatedRequest(url: string, options: RequestInit = {}) {
        const token = localStorage.getItem('access_token');
        
        return fetch(url, {
            ...options,
            headers: {
                ...options.headers,
                'Authorization': `Bearer ${token}`
            }
        });
    }
}

// Usage across different subdomains
const authService = new AuthService();

// On app.mycompany.com
authService.makeAuthenticatedRequest('https://api.mycompany.com/users');

// On admin.mycompany.com  
authService.makeAuthenticatedRequest('https://api.mycompany.com/admin/users');
```

## 🔒 **Security Considerations**

### Production Security Checklist

- [ ] Use HTTPS everywhere (`https://` in all URLs)
- [ ] Set strong JWT secrets (min 32 characters)
- [ ] Configure proper CORS origins
- [ ] Use secure cookies in production
- [ ] Implement proper token expiration
- [ ] Add request rate limiting
- [ ] Monitor authentication logs

### CORS Configuration

The service automatically allows:
```javascript
// Development origins (localhost)
http://localhost:3000
http://localhost:3001
http://localhost:8080

// Production origins (from ALLOWED_ORIGINS)
https://mycompany.com
https://app.mycompany.com
https://admin.mycompany.com
```

## 🧪 **Testing Cross-Domain Setup**

### 1. Test Token Generation
```bash
curl -X POST https://identity-service.mycompany.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}'
```

### 2. Test Token Validation
```bash
curl -X POST https://identity-service.mycompany.com/api/v1/auth/validate \
  -H "Content-Type: application/json" \
  -d '{"token":"YOUR_JWT_TOKEN"}'
```

### 3. Test Cross-Origin Request
```bash
# From your app subdomain
curl -X GET https://api.mycompany.com/users \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Origin: https://app.mycompany.com"
```

## 📋 **Deployment Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  app.company.com │    │ admin.company.com│    │  api.company.com │
│                 │    │                 │    │                 │
│ Frontend App    │    │ Admin Dashboard │    │ API Gateway     │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │ JWT Validation
                    ┌─────────────▼─────────────┐
                    │ identity.company.com      │
                    │                           │
                    │ Identity Service          │
                    │ (Port 8080)               │
                    └───────────────────────────┘
```

## 🚀 **Benefits of This Setup**

1. **Single Sign-On**: Users login once, access all services
2. **Scalable**: Each service validates tokens independently
3. **Secure**: JWT tokens expire and can be revoked
4. **Flexible**: Fine-grained permissions per service
5. **Stateless**: No server-side session storage needed
6. **Cross-Platform**: Works with web, mobile, API services

This setup ensures your authentication works seamlessly across all your company's subdomains while maintaining security and scalability.