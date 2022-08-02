package subcommand

import (
	"os"

	"github.com/phuslu/log"
	"github.com/rotisserie/eris"

	"github.com/morphysm/famed-annotated/config"
)

type Init struct{}

func (*Init) Help() string {
	return "This will create a project configuration file called famed-annotated.yaml. Edit\n    this file to configure the project name and description as well the source\n    code paths for famed-annotated to scan.\n    This command will also create the threatmodel directory in the current\n    path. This directory contains the json output files from famed-annotated run.\n    The following file contains the collection of mitigations, acceptances,\n    connections etc identified as annotations in code:\n        threatmodel/threatmodel.json\n    The following three threat model library files are loaded each time famed-annotated\n    is run. If new threats, controls or components are found, they are added to these\n    files.\n    \n    This allows threats, controls and components to be used across projects\n    and allows you to create threat library files, for example from OWASP or CWE\n    data. When famed-annotated loads paths configured in famed-annotated.yaml, it checks\n    each path to see if a famed-annotated.yaml file exists. If so, it attempts to load the\n    below files.\n    threatmodel/threats.json threatmodel/controls.json threatmodel/components.json"
}

// Run initializes a new famed-annotated project with the configuration file and the directory.
func (a *Init) Run() error {
	err := config.NewDefault()
	if err != nil {
		return eris.Wrap(err, "failed to create configuration file")
	}

	err = os.Mkdir("threatmodel", os.FileMode(0o60))
	if err != nil {
		return eris.Wrap(err, "failed to create threatmodel directory")
	}

	log.Info().Msg("famed-annotated project has been initialised and can now be configured by editing the `famed-annotated.yaml` file in this repository.")

	return nil
}
