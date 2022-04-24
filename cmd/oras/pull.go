package main

import (
	"context"
	"errors"
	"io/ioutil"
	"os"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras/pkg"
	"oras.land/oras/pkg/auth"
	"oras.land/oras/pkg/auth/docker"
)

type (
	pullOptions struct {
		targetRef          string
		allowedMediaTypes  []string
		allowAllMediaTypes bool
		keepOldFiles       bool
		pathTraversal      bool
		output             string
		manifestConfigRef  string
		verbose            bool
		cacheRoot          string

		debug     bool
		configs   []string
		username  string
		password  string
		credType  string
		insecure  bool
		plainHTTP bool
	}
)

func pullCmd() *cobra.Command {
	var opts pullOptions
	cmd := &cobra.Command{
		Use:   "pull <name:tag|name@digest>",
		Short: "Pull files from remote registry",
		Long: `Pull files from remote registry

Example - Pull only files with the "application/vnd.oci.image.layer.v1.tar" media type (default):
  oras pull localhost:5000/hello:latest

Example - Pull only files with the custom "application/vnd.me.hi" media type:
  oras pull localhost:5000/hello:latest -t application/vnd.me.hi

Example - Pull all files, any media type:
  oras pull localhost:5000/hello:latest -a

Example - Pull files from the insecure registry:
  oras pull localhost:5000/hello:latest --insecure

Example - Pull files from the HTTP registry:
  oras pull localhost:5000/hello:latest --plain-http

Example - Pull files with local cache:
  export ORAS_CACHE=~/.oras/cache
  oras pull localhost:5000/hello:latest
`,
		Args: cobra.ExactArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			opts.cacheRoot = os.Getenv("ORAS_CACHE")
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.targetRef = args[0]
			return runPull(opts)
		},
	}

	cmd.Flags().StringArrayVarP(&opts.allowedMediaTypes, "media-type", "t", nil, "allowed media types to be pulled")
	cmd.Flags().BoolVarP(&opts.allowAllMediaTypes, "allow-all", "a", false, "allow all media types to be pulled")
	cmd.Flags().BoolVarP(&opts.keepOldFiles, "keep-old-files", "k", false, "do not replace existing files when pulling, treat them as errors")
	cmd.Flags().BoolVarP(&opts.pathTraversal, "allow-path-traversal", "T", false, "allow storing files out of the output directory")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "output directory")
	cmd.Flags().StringVarP(&opts.manifestConfigRef, "manifest-config", "", "", "output manifest config file")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "v", false, "verbose output")

	cmd.Flags().BoolVarP(&opts.debug, "debug", "d", false, "debug mode")
	cmd.Flags().StringArrayVarP(&opts.configs, "config", "c", nil, "auth config path")
	cmd.Flags().StringVarP(&opts.username, "username", "u", "", "registry username")
	cmd.Flags().StringVarP(&opts.password, "password", "p", "", "registry password")
	cmd.Flags().StringVarP(&opts.credType, "cred-type", "", auth.DOCKER_CREDENTIAL_TYPE, "type of the saved credential")
	cmd.Flags().BoolVarP(&opts.insecure, "insecure", "", false, "allow connections to SSL registry without certs")
	cmd.Flags().BoolVarP(&opts.plainHTTP, "plain-http", "", false, "use plain http and not https")
	return cmd
}

func runPull(opts pullOptions) error {
	ctx := context.Background()
	if !opts.verbose {
		logger := logrus.New()
		logger.Out = ioutil.Discard
		e := logger.WithContext(ctx)
		ctx = context.WithValue(ctx, loggerKey{}, e)
	}

	if opts.debug {
		logrus.SetLevel(logrus.DebugLevel)
		ctx = pkg.TracedContext(ctx)
	}

	if opts.allowAllMediaTypes { // TODO: workaround
		opts.allowedMediaTypes = nil
	} else if len(opts.allowedMediaTypes) == 0 {
		opts.allowedMediaTypes = []string{ocispec.MediaTypeImageLayer, ocispec.MediaTypeImageLayerGzip}
	}

	ref, err := registry.ParseReference(opts.targetRef)
	if err != nil {
		return err
	}

	switch opts.credType {
	case auth.DOCKER_CREDENTIAL_TYPE:
		client, err := docker.NewClient()
		if err != nil {
			return err
		}
		opts.username, opts.password = client.LoadCredential(ctx, ref.Registry)
	default:
		return errors.New("Unsupported credential type '" + opts.credType + "'")
	}

	reg, err := remote.NewRegistry(ref.Registry)
	if err != nil {
		return err
	}
	reg.PlainHTTP = opts.plainHTTP

	settings := auth.LoginSettings{
		Context:   ctx,
		Hostname:  ref.Registry,
		Username:  opts.username,
		Secret:    opts.password,
		Insecure:  opts.insecure,
		UserAgent: pkg.GetUserAgent(),
	}
	reg.Client = settings.GetAuthClient()

	repo, err := reg.Repository(ctx, ref.Repository)
	if err != nil {
		return err

	}
	pwd, err := os.Getwd()
	if err != nil {
		return err
	}
	var src, dst oras.Target = repo, file.New(pwd)
	if opts.cacheRoot != "" {
		cache, err := oci.New(opts.cacheRoot)
		if err != nil {
			return err
		}
		if _, err = oras.Copy(ctx, src, ref.Reference, cache, ref.Reference); err != nil {
			return err
		}
		src = cache
	}
	if _, err = oras.Copy(ctx, src, ref.Reference, dst, ref.Reference); err != nil {
		return err
	}

	return nil
}
