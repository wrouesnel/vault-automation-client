package server

import (
	"context"
	"fmt"
	"github.com/flosch/pongo2/v6"
	"github.com/labstack/echo/v4"
	"github.com/samber/lo"
	"github.com/wrouesnel/vault-automation-client/assets"
	"github.com/wrouesnel/vault-automation-client/pkg/pongorenderer"
	"go.uber.org/zap"
	"go.withmatt.com/httpheaders"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

// LivenessResponse is a common type for responding to K8S style liveness checks.
type LivenessResponse struct {
	RespondedAt time.Time `json:"responded_at"`
}

// ReadinessResponse is a common type for responding to K8S style readiness checks.
type ReadinessResponse struct {
	RespondedAt time.Time `json:"responded_at"`
}

// StartedResonse is a common type for responding to K8S style startup checks.
type StartedResponse struct {
	RespondedAt time.Time `json:"responded_at"`
}

// Liveness implements the interface to wire up a Liveness check from another subsystem
type Liveness interface {
	Liveness() time.Time
}

type MonitorServerConfig struct {
	// Ctx should be a context object which can signal server shutdown. If nil, not used.
	Ctx      context.Context `kong:"-"`
	Liveness Liveness        `kong:"-"`

	Prefix string `help:"Prefix the API is bing served under, if any"`
	Host   string `help:"Host the API should be served on" default:""`
	Port   int    `help:"Port to serve on" default:"8080"`
}

// MonitorServer starts the monitoring web service
func MonitorServer(serverConfig MonitorServerConfig, assetConfig assets.Config, templateGlobals pongo2.Context, configFns ...func(e *echo.Echo) error) context.Context {
	logger := zap.L().With(zap.String("subsystem", "monitor"))

	e := echo.New()
	e.HideBanner = true
	e.Logger.SetOutput(io.Discard)

	// Configure main renderer to use pongo2
	webAssets := lo.Must(fs.Sub(assets.Assets(), "web"))
	webTemplateSet := pongo2.NewSet("web", pongo2.NewFSLoader(webAssets))
	webTemplateSet.Debug = assetConfig.DebugTemplates
	webTemplateSet.Globals = templateGlobals
	e.Renderer = pongorenderer.NewRenderer(webTemplateSet)

	unsealerMonitor := monitor{liveness: serverConfig.Liveness}

	// Add ready and liveness endpoints
	e.GET("/-/ready", unsealerMonitor.Ready)
	e.GET("/-/live", unsealerMonitor.Live)
	e.GET("/-/started", unsealerMonitor.Started)

	// Add static hosting endpoints
	e.GET("/", Index)

	e.GET("/css/*", StaticGet(webAssets, "text/css"))
	e.HEAD("/css/*", StaticHead(webAssets, "text/css"))

	e.GET("/js/*", StaticGet(webAssets, "application/javascript"))
	e.HEAD("/js/*", StaticHead(webAssets, "application/javascript"))

	var ctx context.Context
	if serverConfig.Ctx == nil {
		ctx = context.Background()
	} else {
		ctx = serverConfig.Ctx
	}

	ctx, cancelFn := context.WithCancel(ctx)

	go func() {
		if err := e.Start(fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port)); err != nil {
			logger.Error("Error from server", zap.Error(err))
			cancelFn()
		}
	}()

	return ctx
}

func StaticGet(root fs.FS, mimeType string) echo.HandlerFunc {
	return func(c echo.Context) error {
		urlPath := strings.TrimLeft(c.Request().URL.Path, "/")
		fdata, err := root.Open(urlPath)
		if err != nil {
			return c.HTML(http.StatusNotFound, "Not Found")
		}

		st, err := fdata.Stat()
		if err != nil {
			return c.HTML(http.StatusInternalServerError, "Internal Server Error")
		}

		c.Response().Header().Set(httpheaders.ContentLength, fmt.Sprintf("%v", st.Size()))
		c.Response().Header().Set(httpheaders.LastModified, st.ModTime().UTC().Format(time.RFC1123))

		return c.Stream(http.StatusOK, mimeType, fdata)
	}
}

func StaticHead(root fs.FS, mimeType string) echo.HandlerFunc {
	return func(c echo.Context) error {
		urlPath := strings.TrimLeft(c.Request().URL.Path, "/")
		fdata, err := root.Open(urlPath)
		if err != nil {
			return c.HTML(http.StatusNotFound, "Not Found")
		}

		st, err := fdata.Stat()
		if err != nil {
			return c.HTML(http.StatusInternalServerError, "Internal Server Error")
		}

		c.Response().Header().Set(httpheaders.ContentLength, fmt.Sprintf("%v", st.Size()))
		c.Response().Header().Set(httpheaders.LastModified, st.ModTime().UTC().Format(time.RFC1123))
		return c.NoContent(http.StatusOK)
	}
}

type monitor struct {
	liveness Liveness
}

// Live returns 200 OK if the application server is still functional and able
// to handle requests.
func (um *monitor) Live(c echo.Context) error {
	c.Response().Header().Set(httpheaders.CacheControl, "no-cache")
	t := um.liveness.Liveness()
	if t.IsZero() {
		return c.JSON(http.StatusInternalServerError, nil)
	}

	resp := &LivenessResponse{RespondedAt: t}
	return c.JSON(http.StatusOK, resp)
}

// Ready returns 200 OK if the application is ready to serve new requests.
func (um *monitor) Ready(c echo.Context) error {
	c.Response().Header().Set(httpheaders.CacheControl, "no-cache")
	t := um.liveness.Liveness()
	if t.IsZero() {
		return c.JSON(http.StatusInternalServerError, nil)
	}

	resp := &ReadinessResponse{RespondedAt: t}
	return c.JSON(http.StatusOK, resp)
}

// Started returns 200 OK once the application is started.
func (um *monitor) Started(c echo.Context) error {
	c.Response().Header().Set(httpheaders.CacheControl, "no-cache")
	t := um.liveness.Liveness()
	if t.IsZero() {
		return c.JSON(http.StatusInternalServerError, nil)
	}

	resp := &StartedResponse{RespondedAt: t}
	return c.JSON(http.StatusOK, resp)
}

func Index(c echo.Context) error {
	c.Response().Header().Set(httpheaders.CacheControl, "no-cache")
	return c.Render(http.StatusOK, "index.p2.html", nil)
}
