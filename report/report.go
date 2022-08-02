package report

import (
	"fmt"
	"os"

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

	md.WriteTitle("hello", LevelTitle)

	l := &library.Library{
		Components: map[string]library.Component{},
		Controls:   map[string]library.Control{},
		Threats:    map[string]library.Threat{},
	}
	err := l.ReadFiles()
	if err != nil {
		return "", err
	}

	for name, component := range l.Components {
		fmt.Println(name)

		fmt.Println(component)
	}

	return md.String(), nil
}
