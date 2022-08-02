
# famed-annotated

famed-annotated is an open source project that aims to close the gap between development and security by bringing the threat modelling process further into the development process. This is achieved by having developers and security engineers write threat specifications alongside code, then dynamically generating reports and data-flow diagrams from the code. This allows engineers to capture the security context of the code they write, as they write it.

This project is a reimplementation in [Go](https://go.dev/) of the [threatspec](https://github.com/threatspec/threatspec) specification.

# How does it work?

## Annotate your code

    // @accepts arbitrary file writes to WebApp:FileSystem with filename restrictions
    // @mitigates WebApp:FileSystem against unauthorised access with strict file permissions
    func (p *Page) save() error {
        filename := p.Title + ".txt"
        return ioutil.WriteFile(filename, p.Body, 0600)
    }

## Init and run threatspec
In the same directory

    $ famed-annotated init && famed-annotated run

## Generate report

    $ famed-annotated report

# Roadmap

- Improve the rendering of the report with mermaid diagrams
- Add a report history
- Add a difference checker based on the checksum of the content of functions.
- Add more parser for C/C++, Javascript, Rust, Solidity and more..

# threatspec

This project uses parts of the [threatspec](https://github.com/threatspec/threatspec) project which is itself licensed by MIT.
