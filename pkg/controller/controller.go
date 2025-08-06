//SPDX-License-Identifier: Apache-2.0

package controller

import (
	"github.com/loopholelabs/logging/types"

	"github.com/loopholelabs/auth/internal/db"
	"github.com/loopholelabs/auth/pkg/controller/flows/github"
	"github.com/loopholelabs/auth/pkg/controller/flows/google"
)

type Controller struct {
	logger types.Logger
	db     *db.DB

	github *github.Github
	google *google.Google
}

func New(db *db.DB, logger types.Logger) *Controller {
	return &Controller{
		logger: logger.SubLogger("CONTROLLER"),
		db:     db,
	}
}
