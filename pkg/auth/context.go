package auth

import "context"

type contextKey string

const userClaimsKey contextKey = "user_claims"

// WithUserClaims adds user claims to the context
func WithUserClaims(ctx context.Context, claims *UserClaims) context.Context {
	return context.WithValue(ctx, userClaimsKey, claims)
}

// UserClaimsFromContext retrieves user claims from the context
func UserClaimsFromContext(ctx context.Context) (*UserClaims, bool) {
	claims, ok := ctx.Value(userClaimsKey).(*UserClaims)
	return claims, ok
}

// MustUserClaimsFromContext retrieves user claims from context, panics if not found
func MustUserClaimsFromContext(ctx context.Context) *UserClaims {
	claims, ok := UserClaimsFromContext(ctx)
	if !ok {
		panic("user claims not found in context")
	}
	return claims
}