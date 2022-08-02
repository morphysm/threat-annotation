package report

import (
	"os"
	"time"

	"github.com/rotisserie/eris"

	"github.com/morphysm/famed-annotated/library"
)

func FileReport() error {
	report, err := report()
	if err != nil {
		return eris.Wrap(err, "failed to retrieve report")
	}

	err = os.WriteFile("report.md", []byte(report), 0o600)
	if err != nil {
		return eris.Wrap(err, "failed to write file")
	}

	return nil
}

func report() (string, error) {
	md := NewMarkdown()

	md.WriteTitle("famed-annotated report "+time.Now().Format(time.RFC822), 1)

	l := &library.Library{
		Components: map[string]library.Component{},
		Controls:   map[string]library.Control{},
		Threats:    map[string]library.Threat{},
	}
	err := l.ReadFiles()
	if err != nil {
		return "", err
	}

	md.Writeln()
	md.WriteTitle("Components", 2)
	for _, component := range l.Components {
		md.Writeln()

		md.WriteTitle(component.Name, 3)
		md.Write(component.Id)
		md.Write(component.Description)
	}

	md.Writeln()
	md.WriteTitle("Controls", 2)
	for _, control := range l.Controls {
		md.Writeln()

		md.WriteTitle(control.Name, 3)
		md.Write(control.Id)
		md.Write(control.Description)
	}

	md.Writeln()
	md.WriteTitle("Threats", 2)
	for _, threat := range l.Threats {
		md.Writeln()

		md.WriteTitle(threat.Name, 3)
		md.Write(threat.Id)
		md.Write(threat.Description)
	}

	return md.String(), nil
}
