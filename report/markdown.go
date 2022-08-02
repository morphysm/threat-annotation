package report

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

const (
	LevelTitle  = 3
	LevelNormal = 5
	LevelWord   = 6
)

type Markdown struct {
	builder *strings.Builder
}

func NewMarkdown() *Markdown {
	m := new(Markdown)
	m.builder = new(strings.Builder)

	return m
}

func (m *Markdown) WriteLevel1Title(content string) *Markdown {
	m.WriteTitle(content, 1)
	return m
}

func (m *Markdown) write(content string) {
	m.builder.WriteString(content)
}

func (m *Markdown) GetTitle(content string, level int) string {
	return strings.Repeat("#", level) + " " + content
}

func (m *Markdown) WriteTitle(content string, level int) *Markdown {
	m.write(m.GetTitle(content, level))
	m.Writeln()
	return m
}

func (m *Markdown) WriteWordLine(content string) *Markdown {
	m.Write(content)
	m.Writeln()
	return m
}

func (m *Markdown) Write(content string) *Markdown {
	m.write(content)
	return m
}

func (m *Markdown) Writeln() *Markdown {
	m.write("\n")
	return m
}

func (m *Markdown) WriteLines(lines int) *Markdown {
	for i := 0; i < lines; i++ {
		m.Writeln()
	}
	return m
}

func (m *Markdown) WriteJson(content string) *Markdown {
	m.WriteMultiCode(content, "json")
	return m
}

func (m *Markdown) GetMultiCode(content, t string) string {
	return fmt.Sprintf("``` %s\n%s\n```\n", t, content)
}

func (m *Markdown) WriteMultiCode(content, t string) *Markdown {
	m.write(m.GetMultiCode(content, t))
	return m
}

func (m *Markdown) WriteCodeLine(content string) *Markdown {
	m.WriteCode(content)
	m.Writeln()
	return m
}

func (m *Markdown) GetCode(content string) string {
	return fmt.Sprintf("`%s`", content)
}

func (m *Markdown) WriteCode(content string) *Markdown {
	m.write(m.GetCode(content))
	return m
}

func (m *Markdown) GetTable(t *Table) string {
	return t.String()
}

func (m *Markdown) WriteTable(t *Table) *Markdown {
	m.write(m.GetTable(t))
	return m
}

func (m *Markdown) Export(filename string) error {
	return ioutil.WriteFile(filename, []byte(m.builder.String()), os.ModePerm)
}

func (m *Markdown) GetLink(desc, url string) string {
	return fmt.Sprintf("[%s](%s)", desc, url)
}

func (m *Markdown) WriteLink(desc, url string) *Markdown {
	m.write(m.GetLink(desc, url))
	return m
}

func (m *Markdown) WriteLinkLine(desc, url string) *Markdown {
	m.WriteLink(desc, url)
	m.WriteLines(2)
	return m
}

func (m *Markdown) String() string {
	return m.builder.String()
}

type Table struct {
	body [][]string
}

func (t *Table) SetTitle(col int, content string) *Table {
	t.body[0][col] = content
	return t
}

func (t *Table) SetContent(row, col int, content string) *Table {
	row = row + 2
	t.body[row][col] = content
	return t
}

func (t *Table) String() string {
	var buffer strings.Builder
	for _, row := range t.body {
		buffer.WriteString("|")
		for _, col := range row {
			buffer.WriteString(col)
			buffer.WriteString("|")
		}
		buffer.WriteString("\n")
	}
	return buffer.String()
}

func NewTable(row, col int) *Table {
	t := new(Table)
	row = row + 2
	t.body = make([][]string, row)
	for i := 0; i < row; i++ {
		t.body[i] = make([]string, col)
		if i == 1 {
			for j := 0; j < col; j++ {
				t.body[i][j] = "----"
			}
		}
	}
	return t
}
