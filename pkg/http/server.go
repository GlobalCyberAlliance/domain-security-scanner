package http

import (
	"context"
	"net/http"
	"time"

	"github.com/GlobalCyberAlliance/domain-security-scanner/pkg/advisor"
	"github.com/GlobalCyberAlliance/domain-security-scanner/pkg/scanner"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"github.com/spf13/cast"
)

// Server represents the HTTP server
type Server struct {
	apiPath string
	handler http.Handler
	logger  zerolog.Logger
	server  *http.Server
	router  huma.API

	Addr     string
	CheckTls bool

	// Services used by the various HTTP routes
	Advisor *advisor.Advisor
	Scanner *scanner.Scanner
}

// NewServer returns a new instance of Server
func NewServer(logger zerolog.Logger, version string) *Server {
	server := Server{
		apiPath: "/api/v1",
		logger:  logger,
	}

	config := huma.DefaultConfig("Domain Security Scanner", version)
	config.Info.Description = "The Domain Security Scanner can be used to perform scans against domains for DKIM, DMARC, and SPF DNS records. You can also serve this functionality via an API, or a dedicated mailbox. A web application is also available if organizations would like to perform a single domain scan for DKIM, DMARC or SPF at https://dmarcguide.globalcyberalliance.org."
	config.DocsPath = "" // disable Huma's Stoplight handler
	config.OpenAPIPath = "/api/v1/docs"

	mux := chi.NewMux()
	mux.Use(httprate.Limit(3, 3*time.Second,
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			response, err := json.Marshal(huma.Error429TooManyRequests("try again later"))
			if err != nil {
				http.Error(w, "an error occurred", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(429)
			if _, err = w.Write(response); err != nil {
				return
			}
		}),
	))
	mux.NotFound(func(w http.ResponseWriter, r *http.Request) {
		// redirect to the API docs
		http.Redirect(w, r, server.apiPath+"/docs", http.StatusFound)
	})
	mux.Handle("/api/v1/version", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"version":"` + version + `"}`)); err != nil {
			return
		}
	}))

	server.router = humachi.New(mux, config)
	server.router.Adapter().Handle(&huma.Operation{
		Method: http.MethodGet,
		Path:   server.apiPath + "/docs",
	}, func(ctx huma.Context) {
		ctx.SetHeader("Content-Type", "text/html")
		ctx.BodyWriter().Write([]byte(`<!doctype html><html lang=en><head><title>Domain Security Scanner - API Reference</title><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><style>body{margin:0}</style><style>:root{--theme-font:'Inter',var(--system-fonts)}.light-mode{--theme-color-1:rgb(9, 9, 11);--theme-color-2:rgb(113, 113, 122);--theme-color-3:rgba(25, 25, 28, 0.5);--theme-color-accent:rgba(14, 29, 72);--theme-background-1:#fff;--theme-background-2:#f4f4f5;--theme-background-3:#e3e3e6;--theme-background-accent:#212E56;--theme-border-color:rgb(228, 228, 231);--theme-button-1:rgb(49 53 56);--theme-button-1-color:#fff13;--theme-button-1-hover:rgb(28 31 33);--theme-color-green:#069061;--theme-color-red:#ef0006;--theme-color-yellow:#edbe20;--theme-color-blue:#0082d0;--theme-color-orange:#fb892c;--theme-color-purple:#5203d1;--theme-scrollbar-color:rgba(0, 0, 0, 0.18);--theme-scrollbar-color-active:rgba(0, 0, 0, 0.36)}.dark-mode{--theme-color-1:#fafafa;--theme-color-2:rgb(161, 161, 170);--theme-color-3:rgba(255, 255, 255, 0.533);--theme-color-accent:var(--theme-color-1);--theme-background-1:#000e23;--theme-background-2:#01132e;--theme-background-3:#03193b;--theme-background-accent:#8ab4f81f;--theme-border-color:rgba(255, 255, 255, 0.12);--theme-code-language-color-supersede:var(--theme-color-1);--theme-button-1:#f6f6f6;--theme-button-1-color:#000;--theme-button-1-hover:#e7e7e7;--theme-color-green:rgba(69, 255, 165, 0.823);--theme-color-red:#ff8589;--theme-color-yellow:#ffcc4d;--theme-color-blue:#6bc1fe;--theme-color-orange:#f98943;--theme-color-purple:#b191f9;--theme-scrollbar-color:rgba(255, 255, 255, 0.24);--theme-scrollbar-color-active:rgba(255, 255, 255, 0.48)}.dark-mode .t-doc__sidebar,.light-mode .t-doc__sidebar{--sidebar-background-1:transparent;--sidebar-item-hover-color:currentColor;--sidebar-item-hover-background:var(--theme-background-2);--sidebar-item-active-background:var(--theme-background-3);--sidebar-border-color:var(--theme-border-color);--sidebar-color-1:var(--theme-color-1);--sidebar-color-2:var(--theme-color-2);--sidebar-color-active:var(--theme-color-accent);--sidebar-search-background:rgba(255, 255, 255, 0.1);--sidebar-search-border-color:var(--theme-border-color);--sidebar-search--color:var(--theme-color-3);z-index:1}.light-mode .t-doc__sidebar{--sidebar-search-background:white}.show-api-client-button:before{background:#fff!important}.show-api-client-button span,.show-api-client-button svg{color:#000!important}.download-cta,.references-rendered .markdown a{text-decoration:underline!important}@keyframes headerbackground{from{background:0 0;backdrop-filter:none}to{background:var(--header-background-1);backdrop-filter:blur(12px)}}.dark-mode .t-doc__header,.light-mode .t-doc__header{animation:forwards headerbackground;animation-timeline:scroll();animation-range:0px 200px}.dark-mode .markdown h1,.dark-mode .markdown h2,.dark-mode .markdown h3,.dark-mode .markdown h4,.dark-mode .markdown h5,.dark-mode .markdown h6,.dark-mode .t-editor__page-title h1,.dark-mode h1.section-header,.dark-mode h2.t-editor__heading{-webkit-text-fill-color:transparent;background-image:linear-gradient(to right bottom,#fff 30%,rgba(255,255,255,.38));-webkit-background-clip:text;background-clip:text}.sidebar-heading-type{color:var(--theme-background-1)!important}.active_page .sidebar-heading-type{color:var(--sidebar-color-1)!important}.sidebar-heading-type:after{content:'';position:absolute;top:0;left:0;width:100%;height:100%;background:linear-gradient(9deg,var(--theme-background-1),transparent);border-radius:30px;opacity:.3}.code-languages-icon{padding:12px!important}.code-languages span{margin-top:5px!important}.section-flare{top:-150px!important;height:100vh;background:linear-gradient(#000,var(--theme-background-1));width:100vw}.light-mode .section-flare{background:linear-gradient(180deg,#f4fdff 30%,transparent 100%)}.light-mode .section-flare-item:first-of-type{--c1:#ffffff;--c2:#eff0f5;--c3:#ffffff;--c4:#ffffff;--c5:#ffffff;--c6:#ffffff;--c7:#ebf2f5;filter:blur(5px);mix-blend-mode:initial}.light-mode .section-flare-item:nth-of-type(2){opacity:.1}</style></head><body><script id=api-reference data-url=` + server.apiPath + `/docs.json></script><script>let configuration={theme:"none"},apiReference=document.getElementById("api-reference");apiReference.dataset.configuration=JSON.stringify(configuration)</script><script src=https://cdn.jsdelivr.net/npm/@scalar/api-reference></script></body></html>`))
	})
	server.registerVersionRoute()
	server.registerScanRoutes()

	return &server
}

func (s *Server) Serve(port int) {
	if port == 0 {
		port = 8080
	}

	portString := cast.ToString(port)

	s.logger.Info().Msg("Starting api server on port " + portString)
	s.logger.Fatal().Err(http.ListenAndServe("0.0.0.0:"+portString, s.router.Adapter())).Msg("an error occurred while hosting the api server")
}

func (s *Server) registerVersionRoute() {
	type VersionResponse struct {
		Body struct {
			Version string `json:"version" doc:"The version of the API." example:"3.0.0"`
		}
	}

	huma.Register(s.router, huma.Operation{
		OperationID: "version",
		Summary:     "Get the version of the API",
		Method:      http.MethodGet,
		Path:        s.apiPath + "version",
		Tags:        []string{"Version"},
	}, func(ctx context.Context, input *struct{}) (*VersionResponse, error) {
		resp := VersionResponse{}
		resp.Body.Version = "3.0.0"
		return &resp, nil
	})
}
