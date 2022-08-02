package subcommand

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/morphysm/famed-annotated/config"
	"github.com/morphysm/famed-annotated/library"
)

type Run struct{}

// Help show the Run subcommand help.
func (*Run) Help() string {
	return "This command loads the configuration file and for each configured path it first\n    checks to see if a famed-annotated.yaml file exists in the path. If it does, it loads\n    the three library json files.\n    Once all the library files have been loaded from the paths, famed-annotated run will\n    recursively parse each file in the path, looking for famed-annotated annotations.\n    \n    You can exclude patterns from being searched (for example 'node_modules') using the\n    'ignore' key for the paths in the configuration file. See the documentation for\n    more information.\n    After all the source files have parsed, famed-annotated run will generate the\n    threatmodel/threatmodel.json file as well as the three library files:\n    threatmodel/threats.json threatmodel/controls.json threatmodel/components.json"
}

// Run starts the source code search process based on the file extension and generates the pre-report in json format.
func (a *Run) Run() error {
	if _, err := config.LoadFile(); err != nil {
		return err
	}

	l := library.Library{
		Components: map[string]library.Component{},
		Controls:   map[string]library.Control{},
		Threats:    map[string]library.Threat{},
	}

	/*
		@accepts arbitrary file writes to WebApp:FileSystem with filename restrictions
		@mitigates WebApp:FileSystem against unauthorised access with strict file permissions
	*/

	// Pares every go files.
	for _, s := range find("./", ".go") {
		dat, _ := os.ReadFile(s)
		f, _ := parser.ParseFile(token.NewFileSet(), "", dat, parser.ParseComments)

		for _, i := range f.Comments {
			l.Parse(i.Text())
		}
	}

	l.SaveFiles()

	return nil
}

func find(root, ext string) []string {
	var a []string
	filepath.WalkDir(root, func(s string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if filepath.Ext(d.Name()) == ext {
			a = append(a, s)
		}
		return nil
	})
	return a
}
