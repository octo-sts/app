// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package appconfig

type Options struct {
	TagName            string
	ConfigKeyDelimiter string
	ConfigFilePath     []string
}

type OptionsApplier func(o *Options)

func WithConfigKeyDelimiter(v string) OptionsApplier {
	return func(o *Options) {
		o.ConfigKeyDelimiter = v
	}
}

func WithConfigFilePath(v ...string) OptionsApplier {
	return func(o *Options) {
		o.ConfigFilePath = v
	}
}

func NewOptions(appliers ...OptionsApplier) *Options {
	options := &Options{
		TagName:            "mapstructure",
		ConfigKeyDelimiter: ".",
	}

	for _, applier := range appliers {
		applier(options)
	}

	return options
}
