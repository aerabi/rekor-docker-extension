package main

import (
	"context"
	"flag"
	"github.com/labstack/echo/middleware"
	"net"
	"net/http"
	"os"

	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

func main() {
	rekorClient, err := NewRekorClient(context.Background())

	if err != nil {
		logger.Fatal(err)
	}

	var socketPath string
	flag.StringVar(&socketPath, "socket", "/run/guest-services/backend.sock", "Unix domain socket to listen on")
	flag.Parse()

	_ = os.RemoveAll(socketPath)

	logger.SetOutput(os.Stdout)

	logMiddleware := middleware.LoggerWithConfig(middleware.LoggerConfig{
		Skipper: middleware.DefaultSkipper,
		Format: `{"time":"${time_rfc3339_nano}","id":"${id}",` +
			`"method":"${method}","uri":"${uri}",` +
			`"status":${status},"error":"${error}"` +
			`}` + "\n",
		CustomTimeFormat: "2006-01-02 15:04:05.00000",
		Output:           logger.Writer(),
	})

	logger.Infof("Starting listening on %s\n", socketPath)
	router := echo.New()
	router.HideBanner = true
	router.Use(logMiddleware)
	startURL := ""

	ln, err := listen(socketPath)
	if err != nil {
		logger.Fatal(err)
	}
	router.Listener = ln

	router.GET("/getEntries", getEntries(rekorClient))

	logger.Fatal(router.Start(startURL))
}

func listen(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}
func getEntries(client *RekorClient) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		uuid := ctx.Param("uuid")
		hash := ctx.Param("hash")
		logIndex := ctx.Param("logIndex")

		var body map[string]interface{}

		if uuid == "" && hash == "" && logIndex == "" {
			return ctx.JSON(http.StatusBadRequest, HTTPMessageBody{Message: "No parameters provided"})
		} else if uuid != "" && hash != "" && logIndex != "" {
			return ctx.JSON(http.StatusBadRequest, HTTPMessageBody{Message: "Too many parameters provided, You should only provide one parameter of uuid, hash or logIndex"})
		}

		var err error
		if uuid != "" {
			body, err = client.GetEntryByUUID(uuid)
		} else if logIndex != "" {
			body, err = client.GetEntriesByLogIndex(logIndex)
		} else if hash != "" {
			body, err = client.GetEntriesByHash(hash)
		}

		if err != nil {
			return ctx.JSON(http.StatusInternalServerError, HTTPMessageBody{Message: err.Error()})
		}

		return ctx.JSON(http.StatusOK, body)
	}
}

type HTTPMessageBody struct {
	Message string
}
