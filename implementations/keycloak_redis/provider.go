package keycloak_redis

import (
	"context"
	"github.com/GeorgiyGusev/auth-library/models"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt"
	"github.com/mitchellh/mapstructure"
	"github.com/redis/go-redis/v9"
	"log/slog"
	pathLib "path"
	"strings"
	"sync"
)

type EndpointRule struct {
	PathPattern string
	Methods     []string
	Roles       []string
}

type Provider struct {
	config           *Config
	redis            *redis.Client
	validate         *validator.Validate
	endpointSecurity []EndpointRule
	m                *sync.RWMutex
	logger           *slog.Logger
}

func NewProvider(
	redis *redis.Client,
	config *Config,
	validate *validator.Validate,
	logger *slog.Logger,
) *Provider {
	return &Provider{
		config:           config,
		redis:            redis,
		validate:         validate,
		m:                &sync.RWMutex{},
		endpointSecurity: []EndpointRule{},
		logger:           logger,
	}
}

func (p *Provider) IsEndpointSecure(endpoint string, method string) bool {
	p.m.RLock()
	defer p.m.RUnlock()

	for _, rule := range p.endpointSecurity {
		matched, _ := pathLib.Match(rule.PathPattern, endpoint)
		if matched && (len(rule.Methods) == 0 || contains(rule.Methods, method)) {
			return true
		}
	}
	return false
}

func (p *Provider) AddEndpointSecurity(
	pathPattern string,
	methods []string,
	roles []string,
) {
	p.m.Lock()
	defer p.m.Unlock()

	p.endpointSecurity = append(p.endpointSecurity, EndpointRule{
		PathPattern: pathPattern,
		Methods:     methods,
		Roles:       roles,
	})
}

func (p *Provider) Authorize(
	ctx context.Context,
	path string,
	method string,
	tokenString string,
) (
	models.UserDetails,
	error,
) {
	token, err := p.VerifyToken(ctx, tokenString)
	if err != nil {
		p.logger.Error("failed to verify token", slog.String("err", err.Error()))
		return models.UserDetails{}, models.InvalidTokenError
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !(ok && token.Valid) {
		p.logger.Error("failed to get claims")
		return models.UserDetails{}, models.InvalidTokenError
	}

	if claims["sub"] == "" || claims["sub"] == nil {
		p.logger.Error("failed to validate sub claim")
		return models.UserDetails{}, models.InvalidTokenError
	}

	err = p.validate.Var(claims["sub"], "uuid4")
	if err != nil {
		p.logger.Error("failed to validate sub claim", slog.String("err", err.Error()))
		return models.UserDetails{}, err
	}

	var userRoles []string
	if resourceAccess, ok := claims["resource_access"].(map[string]interface{}); ok {
		if authClient, ok := resourceAccess[p.config.ClientId].(map[string]interface{}); ok {
			if err := mapstructure.Decode(authClient["roles"], &userRoles); err != nil {
				p.logger.Error("cannot get user roles", slog.String("err", err.Error()))
				userRoles = []string{}
			}
		}
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		userEmail = ""
	}

	userDetails := models.UserDetails{
		Roles:      userRoles,
		UserId:     claims["sub"].(string),
		Email:      userEmail,
		Username:   claims["preferred_username"].(string),
		Name:       claims["name"].(string),
		FamilyName: claims["family_name"].(string),
	}

	p.m.RLock()
	defer p.m.RUnlock()
	for _, rule := range p.endpointSecurity {
		matched, _ := pathLib.Match(rule.PathPattern, path)
		if matched && (len(rule.Methods) == 0 || contains(rule.Methods, method)) {
			if !p.IsUserHaveRoles(rule.Roles, userRoles) {
				p.logger.Error("user doesn't have needed roles", slog.Any("neededRoles", rule.Roles), slog.Any("userRoles", userRoles))
				return userDetails, models.AccessDeniedError
			}
			return userDetails, nil
		}
	}

	p.logger.Error("no security rule matched", slog.String("path", path), slog.String("method", method))
	return userDetails, models.AccessDeniedError
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if strings.EqualFold(v, item) {
			return true
		}
	}
	return false
}
