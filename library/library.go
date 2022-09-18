package library

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"github.com/rotisserie/eris"
)

type (
	Component struct {
		Id          string     `json:"id"`
		RunId       string     `json:"run_id"`
		Name        string     `json:"name"`
		Description string     `json:"description"`
		Paths       [][]string `json:"paths"`
		Custom      struct{}   `json:"custom"`
	}
	Control struct {
		Id          string   `json:"id"`
		RunId       string   `json:"run_id"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Custom      struct{} `json:"custom"`
	}
	Threat struct {
		Id          string   `json:"id"`
		RunId       string   `json:"run_id"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Custom      struct{} `json:"custom"`
	}
	Mitigate struct {
		Control     string   `json:"control"`
		Threat      string   `json:"threat"`
		Component   string   `json:"component"`
		Description string   `json:"description"`
		Custom      struct{} `json:"custom"`
		Source      struct {
			Annotation string `json:"annotation"`
			Code       string `json:"code"`
			Filename   string `json:"filename"`
			Line       int    `json:"line"`
		} `json:"source"`
	}
	Acceptance struct {
		Threat      string   `json:"threat"`
		Component   string   `json:"component"`
		Details     string   `json:"details"`
		Description string   `json:"description"`
		Custom      struct{} `json:"custom"`
		Source      struct {
			Annotation string `json:"annotation"`
			Code       string `json:"code"`
			Filename   string `json:"filename"`
			Line       int    `json:"line"`
		} `json:"source"`
	}
	Exposure struct {
		Threat      string   `json:"threat"`
		Component   string   `json:"component"`
		Details     string   `json:"details"`
		Description string   `json:"description"`
		Custom      struct{} `json:"custom"`
		Source      struct {
			Annotation string `json:"annotation"`
			Code       string `json:"code"`
			Filename   string `json:"filename"`
			Line       int    `json:"line"`
		} `json:"source"`
	}
	Transfer struct {
		Threat               string   `json:"threat"`
		SourceComponent      string   `json:"source_component"`
		DestinationComponent string   `json:"destination_component"`
		Details              string   `json:"details"`
		Description          string   `json:"description"`
		Custom               struct{} `json:"custom"`
		Source               struct {
			Annotation string `json:"annotation"`
			Code       string `json:"code"`
			Filename   string `json:"filename"`
			Line       int    `json:"line"`
		} `json:"source"`
	}
	Connection struct {
		SourceComponent      string   `json:"source_component"`
		DestinationComponent string   `json:"destination_component"`
		Direction            string   `json:"direction"`
		Details              string   `json:"details"`
		Description          string   `json:"description"`
		Custom               struct{} `json:"custom"`
		Source               struct {
			Annotation string `json:"annotation"`
			Code       string `json:"code"`
			Filename   string `json:"filename"`
			Line       int    `json:"line"`
		} `json:"source"`
	}
	Review struct {
		Component   string   `json:"component"`
		Details     string   `json:"details"`
		Description string   `json:"description"`
		Custom      struct{} `json:"custom"`
		Source      struct {
			Annotation string `json:"annotation"`
			Code       string `json:"code"`
			Filename   string `json:"filename"`
			Line       int    `json:"line"`
		} `json:"source"`
	}
	Test struct {
		Component   string   `json:"component"`
		Control     string   `json:"control"`
		Description string   `json:"description"`
		Custom      struct{} `json:"custom"`
		Source      struct {
			Annotation string `json:"annotation"`
			Code       string `json:"code"`
			Filename   string `json:"filename"`
			Line       int    `json:"line"`
		} `json:"source"`
	}
	Threatmodel struct {
		Mitigations []Mitigate   `json:"mitigations"`
		Exposures   []Exposure   `json:"exposures"`
		Transfers   []Transfer   `json:"transfers"`
		Acceptances []Acceptance `json:"acceptances"`
		Connections []Connection `json:"connections"`
		Reviews     []Review     `json:"reviews"`
		Tests       []Test       `json:"tests"`
		RunId       string       `json:"run_id"`
	}
	Library struct {
		Components  map[string]Component
		Controls    map[string]Control
		Threats     map[string]Threat
		ThreatModel Threatmodel
	}
)

const (
	componentRe = `(?m)@component (?P<component>.*)`
	controlRe   = `(?m)@control (?P<control>.*)`
	threatRe    = `(?m)@threat (?P<threat>.*)`

	mitigateRe = `(?m)@mitigates? (?P<component>.*?) against (?P<threat>.*?) with (?P<control>.*)`
	acceptRe   = `(?m)@accepts? (?P<threat>.*?) to (?P<component>.*?) with (?P<details>.*)`
	transferRe = `(?m)@transfers? (?P<threat>.*?) from (?P<source_component>.*?) to (?P<destination_component>.*?) with (?P<details>.*)`
	exposeRe   = `(?m)@exposes? (?P<component>.*?) to (?P<threat>.*?) with (?P<details>.*)`
	connectRe  = `(?m)@connects? (?P<source_component>.*?) (?P<direction>with|to) (?P<destination_component>.*?) with (?P<details>.*)`
	reviewRe   = `(?m)@reviews? (?P<component>.*?) (?P<details>.*)`
	testRe     = `(?m)@tests? (?P<control>.*?) for (?P<component>.*)`
)

// Parse deduces from comment and adds to the library everything that is compatible with the specification.
func (l *Library) Parse(comment string) {
	// component
	re := regexp.MustCompile(componentRe)
	re.FindStringSubmatch(comment)
	for _, match := range re.FindAllString(comment, -1) {
		comp := Component{Name: re.FindStringSubmatch(match)[1]}
		l.addComponent(&comp)
	}

	// controlRe
	re = regexp.MustCompile(controlRe)
	re.FindStringSubmatch(comment)
	for _, match := range re.FindAllString(comment, -1) {
		cont := Control{Name: re.FindStringSubmatch(match)[1]}
		l.addControl(&cont)
	}

	// threatRe
	re = regexp.MustCompile(threatRe)
	re.FindStringSubmatch(comment)
	for _, match := range re.FindAllString(comment, -1) {
		threat := Threat{Name: re.FindStringSubmatch(match)[1]}
		l.addThreat(&threat)
	}

	// mitigateRe
	re = regexp.MustCompile(mitigateRe)
	re.FindStringSubmatch(comment)
	for _, match := range re.FindAllString(comment, -1) {
		mitigate := Mitigate{
			Control:   re.FindStringSubmatch(match)[3],
			Threat:    re.FindStringSubmatch(match)[2],
			Component: re.FindStringSubmatch(match)[1],
		}
		l.addMitigate(&mitigate)
	}

	// acceptRe
	re = regexp.MustCompile(acceptRe)
	re.FindStringSubmatch(comment)
	for _, match := range re.FindAllString(comment, -1) {
		acceptance := Acceptance{
			Threat:    re.FindStringSubmatch(match)[2],
			Component: re.FindStringSubmatch(match)[1],
		}
		l.addAcceptance(&acceptance)
	}

	// exposeRe
	re = regexp.MustCompile(exposeRe)
	re.FindStringSubmatch(comment)
	for _, match := range re.FindAllString(comment, -1) {
		expose := Exposure{
			Threat:    re.FindStringSubmatch(match)[3],
			Component: re.FindStringSubmatch(match)[1],
			Details:   re.FindStringSubmatch(match)[2],
		}
		l.addExposure(&expose)
	}

	// transferRe
	re = regexp.MustCompile(transferRe)
	re.FindStringSubmatch(comment)
	for _, match := range re.FindAllString(comment, -1) {
		transfer := Transfer{
			Threat:               re.FindStringSubmatch(match)[1],
			SourceComponent:      re.FindStringSubmatch(match)[2],
			DestinationComponent: re.FindStringSubmatch(match)[3],
			Details:              re.FindStringSubmatch(match)[4],
		}
		l.addTransfer(&transfer)
	}

	// connectRe
	re = regexp.MustCompile(connectRe)
	re.FindStringSubmatch(comment)
	for _, match := range re.FindAllString(comment, -1) {
		connection := Connection{
			SourceComponent:      re.FindStringSubmatch(match)[4],
			DestinationComponent: re.FindStringSubmatch(match)[3],
			Direction:            re.FindStringSubmatch(match)[2],
			Details:              re.FindStringSubmatch(match)[1],
		}
		l.addConnection(&connection)
	}

	// reviewRe
	re = regexp.MustCompile(reviewRe)
	re.FindStringSubmatch(comment)
	for _, match := range re.FindAllString(comment, -1) {
		review := Review{
			Component: re.FindStringSubmatch(match)[2],
			Details:   re.FindStringSubmatch(match)[1],
		}
		l.addReview(&review)
	}

	// testRe
	re = regexp.MustCompile(testRe)
	re.FindStringSubmatch(comment)
	for _, match := range re.FindAllString(comment, -1) {
		test := Test{
			Component: re.FindStringSubmatch(match)[2],
			Control:   re.FindStringSubmatch(match)[1],
		}
		l.addTest(&test)
	}
}

func (l *Library) addComponent(component *Component) {
	name, id := parse_name(component.Name)

	if val, ok := l.Components[name]; ok {
		*component = val
	}

	component.Name = name
	splittedName := strings.Split(component.Name, ":")
	component.Paths = append(component.Paths, splittedName[:len(splittedName)-1])
	component.Id = id

	l.Components[component.Id] = *component
}

func (l *Library) addControl(control *Control) {
	name, id := parse_name(control.Name)

	if val, ok := l.Controls[name]; ok {
		*control = val
	}

	control.Name = name
	control.Id = id

	l.Controls[control.Id] = *control
}

func (l *Library) addThreat(threat *Threat) {
	name, id := parse_name(threat.Name)

	if val, ok := l.Threats[name]; ok {
		*threat = val
	}

	threat.Name = name
	threat.Id = id

	l.Threats[threat.Id] = *threat
}

func (l *Library) addMitigate(mitigate *Mitigate) {
	l.addControl(&Control{Name: mitigate.Control})
	l.addThreat(&Threat{Name: mitigate.Threat})
	l.addComponent(&Component{Name: mitigate.Component})

	l.ThreatModel.Mitigations = append(l.ThreatModel.Mitigations, *mitigate)
}

func (l *Library) addAcceptance(acceptance *Acceptance) {
	l.addThreat(&Threat{Name: acceptance.Threat})
	l.addComponent(&Component{Name: acceptance.Component})

	l.ThreatModel.Acceptances = append(l.ThreatModel.Acceptances, *acceptance)
}

func (l *Library) addExposure(e *Exposure) {
	l.addThreat(&Threat{Name: e.Threat})
	l.addComponent(&Component{Name: e.Component})

	l.ThreatModel.Exposures = append(l.ThreatModel.Exposures, *e)
}

func (l *Library) addTransfer(t *Transfer) {
	l.addThreat(&Threat{Name: t.Threat})
	l.addComponent(&Component{Name: t.SourceComponent})
	l.addComponent(&Component{Name: t.DestinationComponent})

	l.ThreatModel.Transfers = append(l.ThreatModel.Transfers, *t)
}

func (l *Library) addConnection(c *Connection) {
	l.addComponent(&Component{Name: c.SourceComponent})
	l.addComponent(&Component{Name: c.DestinationComponent})

	l.ThreatModel.Connections = append(l.ThreatModel.Connections, *c)
}

func (l *Library) addReview(r *Review) {
	l.addComponent(&Component{Name: r.Component})

	l.ThreatModel.Reviews = append(l.ThreatModel.Reviews, *r)
}

func (l *Library) addTest(t *Test) {
	l.addComponent(&Component{Name: t.Component})
	l.addControl(&Control{Name: t.Control})

	l.ThreatModel.Tests = append(l.ThreatModel.Tests, *t)
}

func parse_name(id string) (string, string) {
	return id, id
}

func (l *Library) SaveFiles() {
	os.Mkdir("threatmodel", 0o700)

	file, _ := json.MarshalIndent(l.Controls, "", " ")
	os.WriteFile("threatmodel/controls.json", file, 0o666)

	file, _ = json.MarshalIndent(l.Threats, "", " ")
	os.WriteFile("threatmodel/threats.json", file, 0o666)

	file, _ = json.MarshalIndent(l.Components, "", " ")
	os.WriteFile("threatmodel/components.json", file, 0o666)

	file, _ = json.MarshalIndent(l.ThreatModel, "", " ")
	os.WriteFile("threatmodel/threatModel.json", file, 0o666)
}

func (l *Library) ReadFiles() error {
	controlsFile, err := os.ReadFile("threatmodel/controls.json")
	if err != nil {
		return eris.Wrap(err, "failed to read threatmodel/controls.json")
	}

	threatsFile, err := os.ReadFile("threatmodel/threats.json")
	if err != nil {
		return eris.Wrap(err, "failed to read threatmodel/threats.json")
	}

	componentsFile, err := os.ReadFile("threatmodel/components.json")
	if err != nil {
		return eris.Wrap(err, "failed to read threatmodel/components.json")
	}

	threatModelFile, err := os.ReadFile("threatmodel/threatModel.json")
	if err != nil {
		return eris.Wrap(err, "failed to read threatmodel/threatModel.json")
	}

	err = json.Unmarshal(controlsFile, &l.Controls)
	if err != nil {
		return eris.Wrap(err, "failed to understand threatmodel/controls.json")
	}

	err = json.Unmarshal(threatsFile, &l.Threats)
	if err != nil {
		return eris.Wrap(err, "failed to understand threats/controls.json")
	}

	err = json.Unmarshal(componentsFile, &l.Components)
	if err != nil {
		return eris.Wrap(err, "failed to understand threatmodel/components.json")
	}

	err = json.Unmarshal(threatModelFile, &l.ThreatModel)
	if err != nil {
		return eris.Wrap(err, "failed to understand threatmodel/threatModel.json")
	}

	return nil
}
