package command

import (
	goflag "flag"
	"os"
	"strings"

	"github.com/hashicorp/nomad/api"
	flaghelper "github.com/hashicorp/nomad/helper/flags"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/colorstring"
	"github.com/posener/complete"
	flag "github.com/spf13/pflag"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	// Constants for CLI identifier length
	shortId = 8
	fullId  = 36
)

// FlagSetFlags is an enum to define what flags are present in the
// default FlagSet returned by Meta.FlagSet.
type FlagSetFlags uint

const (
	FlagSetNone    FlagSetFlags = 0
	FlagSetClient  FlagSetFlags = 1 << iota
	FlagSetDefault              = FlagSetClient
)

// Meta contains the meta-options and functionality that nearly every
// Nomad command inherits.
type Meta struct {
	Ui cli.Ui

	// These are set by the command line flags.
	flagAddress string

	// Whether to not-colorize output
	noColor bool

	// The region to send API requests
	region string

	// namespace to send API requests
	namespace string

	// token is used for ACLs to access privileged information
	token string

	caCert        string
	caPath        string
	clientCert    string
	clientKey     string
	tlsServerName string
	insecure      bool
}

// FlagSet returns a FlagSet with the common flags that every
// command implements. The exact behavior of FlagSet can be configured
// using the flags as the second parameter, for example to disable
// server settings on the commands that don't talk to a server.
func (m *Meta) FlagSet(n string, fs FlagSetFlags) *flag.FlagSet {
	f := flag.NewFlagSet(n, flag.ContinueOnError)
	// flag.CommandLine.AddGoFlagSet(goflag.CommandLine)

	// FlagSetClient is used to enable the settings for specifying
	// client connectivity options.
	if fs&FlagSetClient != 0 {
		f.StringVarP(&m.flagAddress, "address", "a", "", "")
		f.StringVarP(&m.region, "region", "r", "", "")
		f.StringVarP(&m.namespace, "namespace", "n", "", "")
		f.BoolVar(&m.noColor, "no-color", false, "")
		f.StringVar(&m.caCert, "ca-cert", "", "")
		f.StringVar(&m.caPath, "ca-path", "", "")
		f.StringVar(&m.clientCert, "client-cert", "", "")
		f.StringVar(&m.clientKey, "client-key", "", "")
		f.BoolVar(&m.insecure, "insecure", false, "")
		f.StringVar(&m.tlsServerName, "tls-server-name", "", "")
		f.BoolVar(&m.insecure, "tls-skip-verify", false, "")
		f.StringVar(&m.token, "token", "", "")
	}

	f.SetOutput(&uiErrorWriter{ui: m.Ui})

	return f
}

// Same as FlagSet, but uses the go flag library instead of pflag
// Used to maintain backwards compatibility
func (m *Meta) OldFlagSet(n string, fs FlagSetFlags) *goflag.FlagSet {
	f := goflag.NewFlagSet(n, goflag.ContinueOnError)

	// FlagSetClient is used to enable the settings for specifying
	// client connectivity options.
	if fs&FlagSetClient != 0 {
		f.StringVar(&m.flagAddress, "address", "", "")
		f.StringVar(&m.region, "region", "", "")
		f.StringVar(&m.namespace, "namespace", "", "")
		f.BoolVar(&m.noColor, "no-color", false, "")
		f.StringVar(&m.caCert, "ca-cert", "", "")
		f.StringVar(&m.caPath, "ca-path", "", "")
		f.StringVar(&m.clientCert, "client-cert", "", "")
		f.StringVar(&m.clientKey, "client-key", "", "")
		f.BoolVar(&m.insecure, "insecure", false, "")
		f.StringVar(&m.tlsServerName, "tls-server-name", "", "")
		f.BoolVar(&m.insecure, "tls-skip-verify", false, "")
		f.StringVar(&m.token, "token", "", "")
	}

	f.SetOutput(&uiErrorWriter{ui: m.Ui})

	return f
}

// AutocompleteFlags returns a set of flag completions for the given flag set.
func (m *Meta) AutocompleteFlags(fs FlagSetFlags) complete.Flags {
	if fs&FlagSetClient == 0 {
		return nil
	}

	return complete.Flags{
		"--address":         complete.PredictAnything,
		"--region":          complete.PredictAnything,
		"--namespace":       NamespacePredictor(m.Client, nil),
		"--no-color":        complete.PredictNothing,
		"--ca-cert":         complete.PredictFiles("*"),
		"--ca-path":         complete.PredictDirs("*"),
		"--client-cert":     complete.PredictFiles("*"),
		"--client-key":      complete.PredictFiles("*"),
		"--insecure":        complete.PredictNothing,
		"--tls-server-name": complete.PredictNothing,
		"--tls-skip-verify": complete.PredictNothing,
		"--token":           complete.PredictAnything,
	}
}

// ApiClientFactory is the signature of a API client factory
type ApiClientFactory func() (*api.Client, error)

// Client is used to initialize and return a new API client using
// the default command line arguments and env vars.
func (m *Meta) clientConfig() *api.Config {
	config := api.DefaultConfig()
	if m.flagAddress != "" {
		config.Address = m.flagAddress
	}
	if m.region != "" {
		config.Region = m.region
	}
	if m.namespace != "" {
		config.Namespace = m.namespace
	}

	// If we need custom TLS configuration, then set it
	if m.caCert != "" || m.caPath != "" || m.clientCert != "" || m.clientKey != "" || m.tlsServerName != "" || m.insecure {
		t := &api.TLSConfig{
			CACert:        m.caCert,
			CAPath:        m.caPath,
			ClientCert:    m.clientCert,
			ClientKey:     m.clientKey,
			TLSServerName: m.tlsServerName,
			Insecure:      m.insecure,
		}
		config.TLSConfig = t
	}

	if m.token != "" {
		config.SecretID = m.token
	}

	return config
}

func (m *Meta) Client() (*api.Client, error) {
	return api.NewClient(m.clientConfig())
}

func (m *Meta) allNamespaces() bool {
	return m.clientConfig().Namespace == api.AllNamespacesNamespace
}

func (m *Meta) Colorize() *colorstring.Colorize {
	return &colorstring.Colorize{
		Colors:  colorstring.DefaultColors,
		Disable: m.noColor || !terminal.IsTerminal(int(os.Stdout.Fd())),
		Reset:   true,
	}
}

type usageOptsFlags uint8

const (
	usageOptsDefault     usageOptsFlags = 0
	usageOptsNoNamespace                = 1 << iota
)

// generalOptionsUsage returns the help string for the global options.
func generalOptionsUsage(usageOpts usageOptsFlags) string {

	helpText := `
  --address=<addr>, -a <addr>
    The address of the Nomad server.
    Overrides the NOMAD_ADDR environment variable if set.
    Default = http://127.0.0.1:4646

  --region=<region>, -r <region>
    The region of the Nomad servers to forward commands to.
    Overrides the NOMAD_REGION environment variable if set.
    Defaults to the Agent's local region.
`

	namespaceText := `
  --namespace=<namespace>, -n <namespace>
    The target namespace for queries and actions bound to a namespace.
    Overrides the NOMAD_NAMESPACE environment variable if set.
    If set to '*', job and alloc subcommands query all namespaces authorized
    to user.
    Defaults to the "default" namespace.
`

	// note: that although very few commands use color explicitly, all of them
	// return red-colored text on error so we don't want to make this
	// configurable
	remainingText := `
  --no-color
    Disables colored command output. Alternatively, NOMAD_CLI_NO_COLOR may be
    set.

  --ca-cert=<path>
    Path to a PEM encoded CA cert file to use to verify the
    Nomad server SSL certificate.  Overrides the NOMAD_CACERT
    environment variable if set.

  --ca-path=<path>
    Path to a directory of PEM encoded CA cert files to verify
    the Nomad server SSL certificate. If both -ca-cert and
    -ca-path are specified, -ca-cert is used. Overrides the
    NOMAD_CAPATH environment variable if set.

  --client-cert=<path>
    Path to a PEM encoded client certificate for TLS authentication
    to the Nomad server. Must also specify -client-key. Overrides
    the NOMAD_CLIENT_CERT environment variable if set.

  --client-key=<path>
    Path to an unencrypted PEM encoded private key matching the
    client certificate from -client-cert. Overrides the
    NOMAD_CLIENT_KEY environment variable if set.

  --tls-server-name=<value>
    The server name to use as the SNI host when connecting via
    TLS. Overrides the NOMAD_TLS_SERVER_NAME environment variable if set.

  --tls-skip-verify
    Do not verify TLS certificate. This is highly not recommended. Verification
    will also be skipped if NOMAD_SKIP_VERIFY is set.

  --token
    The SecretID of an ACL token to use to authenticate API requests with.
    Overrides the NOMAD_TOKEN environment variable if set.
`

	if usageOpts&usageOptsNoNamespace == 0 {
		helpText = helpText + namespaceText
	}

	helpText = helpText + remainingText
	return strings.TrimSpace(helpText)
}

// Defines types for passing flag info to create flag sets
// Used to create flag sets using posix flags and also the non-posix flags
// Putting this here for now since this breaks if it goes into the flaghelper??
type BaseFlagInfo struct {
	name  string
	usage string
	short string
}

type BoolFlagInfo struct {
	BaseFlagInfo
	ptr   *bool
	value bool
}

// This is a regular string flag, not the flaghelper StringFlag type
type StringFlagInfo struct {
	BaseFlagInfo
	ptr   *string
	value string
}

// flaghelper string flag info
type FHStringFlagInfo struct {
	BaseFlagInfo
	ptr *flaghelper.StringFlag
}

type FlagList struct {
	Bools         []BoolFlagInfo
	Strings       []StringFlagInfo
	FHStringFlags []FHStringFlagInfo
}

// Generates the flag sets using posix flags
func genNewFlags(flags FlagList, meta *Meta, name string, help string) *flag.FlagSet {
	flagSet := meta.FlagSet(name, FlagSetClient)
	flagSet.Usage = func() { meta.Ui.Output(help) }
	for _, b := range flags.Bools {
		if b.short != "" {
			flagSet.BoolVarP(b.ptr, b.name, b.short, b.value, b.usage)
		} else {
			flagSet.BoolVar(b.ptr, b.name, b.value, b.usage)
		}
	}

	for _, s := range flags.Strings {
		if s.short != "" {
			flagSet.StringVarP(s.ptr, s.name, s.short, s.value, s.usage)
		} else {
			flagSet.StringVar(s.ptr, s.name, s.value, s.usage)
		}
	}

	for _, sf := range flags.FHStringFlags {
		if sf.short != "" {
			flagSet.VarP(sf.ptr, sf.name, sf.short, sf.usage)
		} else {
			flagSet.Var(sf.ptr, sf.name, sf.usage)
		}
	}

	return flagSet
}

// Essentially the same function as genNewFlags, but this uses the standard
// go flag library to maintain backwards compatibility
func genOldFlags(flags FlagList, meta *Meta, name string) *goflag.FlagSet {
	flagSet := meta.OldFlagSet(name, FlagSetClient)
	for _, b := range flags.Bools {
		flagSet.BoolVar(b.ptr, b.name, b.value, b.usage)
	}
	for _, s := range flags.Strings {
		flagSet.StringVar(s.ptr, s.name, s.value, s.usage)
	}
	for _, sf := range flags.FHStringFlags {
		flagSet.Var(sf.ptr, sf.name, sf.usage)
	}

	return flagSet
}

// Parses the flags and returns the args. It assumes posix flags first, and then if that throws an error,
// falls back to non-posix flags. Assumes either/or, not mixing/matching
func parseFlags(args []string, flags FlagList, meta *Meta, name string, help string) ([]string, error) {
	oldFlags := false
	newFlagSet := genNewFlags(flags, meta, name, help)
	var oldFlagSet *goflag.FlagSet
	if err := newFlagSet.Parse(args); err != nil {
		oldFlagSet = genOldFlags(flags, meta, name)

		if e := oldFlagSet.Parse(args); e != nil {
			return nil, err
		}
		meta.Ui.Warn("Parsing error, falling back to non-posix flags")
		oldFlags = true
	}

	if oldFlags {
		return oldFlagSet.Args(), nil
	}
	return newFlagSet.Args(), nil
}
