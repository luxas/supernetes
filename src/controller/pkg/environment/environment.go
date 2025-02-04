// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package environment

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/supernetes/supernetes/common/pkg/log"
	"github.com/supernetes/supernetes/common/pkg/supernetes"
)

// Environment exposes the dynamic (environment) configuration of the controller
type Environment interface {
	ControllerAddress() *netip.Addr // Return the IP address of the controller, nil if unknown
}

type environment struct {
	controllerAddress netip.Addr
}

// Load acquires and parses the dynamic configuration from the environment
func Load() Environment {
	controllerAddress, err := loadControllerAddress()
	if err != nil {
		log.Warn().Err(err).Msg("controller address unavailable")
	}

	return &environment{
		controllerAddress,
	}
}

func (e *environment) ControllerAddress() *netip.Addr {
	if !e.controllerAddress.IsValid() {
		return nil
	}

	return &e.controllerAddress
}

func loadControllerAddress() (netip.Addr, error) {
	// Take in status.PodIP, don't try to guess it here
	env := os.Getenv(supernetes.ControllerAddress)
	if len(env) == 0 {
		return netip.Addr{}, fmt.Errorf("%s unset", supernetes.ControllerAddress)
	}

	return netip.ParseAddr(env)
}
