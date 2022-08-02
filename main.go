package main

import (
	"time"

	"github.com/alecthomas/kong"
	"github.com/phuslu/log"

	"github.com/morphysm/famed-annotated/subcommand"
)

type Globals struct {
	LogLevel string `short:"l" help:"Set the log level. Must be one of: trace, debug, info, warn, error, fatal, panic." default:"info"`
}

// Arguments are all the possible subcommands, arguments and flags that can be sent to the application.
type Arguments struct {
	Globals
	Init   subcommand.Init   `cmd:"" help:"Initialise famed-annotated in the current directory."`
	Report subcommand.Report `cmd:"" help:"Generate the famed-annotated threat model report."`
	Run    subcommand.Run    `cmd:"" help:"Run famed-annotated against source code files."`
}

func main() {
	arguments := &Arguments{}

	// Parse the arguments and show help if no subcommand is called
	ctx := kong.Parse(arguments,
		kong.Name("famed-annotated"),
		kong.Description("famed-annotated - continuous threat modeling, through code\n    famed-annotated is an open source project that aims to close the gap between\n    development and security by bringing the threat modelling process further\n    into the development process. This is achieved by having developers and\n    security engineers write threat specifications alongside code, then\n    dynamically generating reports and data-flow diagrams from the code. This\n    allows engineers to capture the security context of the code they write,\n    as they write it.\n    \n    Usage:\n    \n    # Initialise famed-annotated in the current directory\n    $ famed-annotated init\n    \n    # Configure the source code paths\n    $ $EDITOR famed-annotated.yaml\n    \n    # Run famed-annotated against the source code paths\n    $ famed-annotated run\n    \n    # Generate the threat mode report\n    $ famed-annotated report\n    \n    For more information for each subcommand use --help. For everything else,\n    visit the website at https://github.com/morphysm/famed-annotated"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}))

	// Instantiate default logger
	log.DefaultLogger = log.Logger{
		Level:      log.ParseLevel(arguments.LogLevel),
		TimeFormat: time.Stamp,
		Writer: &log.ConsoleWriter{
			ColorOutput:    true,
			QuoteString:    true,
			EndWithMessage: false,
		},
	}

	err := ctx.Run(arguments.Globals)
	ctx.FatalIfErrorf(err)
}
