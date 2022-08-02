package subcommand

import (
	"github.com/rotisserie/eris"

	"github.com/morphysm/famed-annotated/report"
)

type Report struct{}

func (*Report) Help() string {
	return "This will by default use Graphviz to generate a visualisation of the threat model,\n    and embed it in a threat model markdown document in the current directory:\n    \n    ThreatModel.md\n    This document contains tables of mitigations etc (including any tests), as\n    well as connections and reviews."
}

func (a *Report) Run() error {
	err := report.FileReport()
	if err != nil {
		return eris.Wrap(err, "failed to generate report file")
	}

	return nil
}
