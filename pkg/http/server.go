package http

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/GlobalCyberAlliance/DomainSecurityScanner/pkg/scanner"
	"github.com/didip/tollbooth/v7"
	"github.com/didip/tollbooth/v7/limiter"
	"github.com/gin-gonic/gin"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/spf13/cast"
)

// Server represents an HTTP server. It is meant to wrap all HTTP functionality
// used by the application so that dependent packages (such as cmd/wtfd) do not
// need to reference the "net/http" package at all.
type Server struct {
	handler http.Handler
	lmt     *limiter.Limiter
	ln      net.Listener
	logger  zerolog.Logger
	server  *http.Server
	router  *gin.Engine

	Addr     string
	CheckTls bool
	Routes   *gin.RouterGroup

	// Services used by the various HTTP routes.
	Scanner *scanner.Scanner
}

// NewServer returns a new instance of Server.
func NewServer(logger zerolog.Logger) *Server {
	gin.SetMode(gin.ReleaseMode)

	rateLimiter := tollbooth.NewLimiter(10, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})
	rateLimiter.SetIPLookups([]string{"RemoteAddr", "X-Forwarded-For", "X-Real-IP"}).
		SetMethods([]string{"GET", "POST"})

	// Create a new server that wraps the net/http server & add a gin router.
	s := &Server{
		logger: logger,
		lmt:    rateLimiter,
		server: &http.Server{},
		router: gin.New(),
	}

	s.router.Use(gin.Logger(), gin.Recovery())

	// Setup error handling routes.
	s.router.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{"message": "not found"})
	})

	v1 := s.router.Group("/api/v1")
	v1.Use(s.handleRateLimit(s.lmt))

	// Register unauthenticated routes.
	{
		s.Routes = v1.Group("")
		s.registerScanRoutes(s.Routes)
	}

	// enable CORS support
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowCredentials: false,
		Debug:            false,
	})

	s.handler = c.Handler(s.router)

	return s
}

func (s *Server) Serve(port int) {
	if port == 0 {
		port = 8080
	}

	portString := cast.ToString(port)

	s.logger.Info().Msg("Starting api server on port " + portString)
	s.logger.Fatal().Err(http.ListenAndServe("0.0.0.0:"+portString, s.handler)).Msg("an error occurred while hosting the api server")
}

func (s *Server) handleRateLimit(lmt *limiter.Limiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		httpError := tollbooth.LimitByRequest(lmt, c.Writer, c.Request)
		if httpError != nil {
			c.Writer.Header().Set("Content-Type", "application/json")
			c.Writer.WriteHeader(429)
			data := map[string]string{"message": "too many requests"}
			if err := json.NewEncoder(c.Writer).Encode(data); err != nil {
				s.logger.Error().Err(err)
			}
			c.Abort()
			return
		} else {
			c.Next()
		}
	}
}

func (s *Server) respond(c *gin.Context, code int, data interface{}) {
	if code/100 == 4 || code/100 == 5 {
		text := fmt.Sprintf("%v", data)
		data = map[string]string{"message": text}
	}

	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(code)
	if code != 204 {
		if err := json.NewEncoder(c.Writer).Encode(data); err != nil {
			s.logger.Fatal().Err(err).Msg("Failed to encode json object")
		}
	}
}
