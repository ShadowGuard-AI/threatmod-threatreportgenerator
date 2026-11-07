# threatmod-ThreatReportGenerator

Generates a threat model report in Markdown format from structured threat data in a JSON input file. Input values are treated as data: markup and Markdown control characters in input values are escaped in the generated report, so they render as inert text rather than live markup or report structure. Reports can include a text based diagram, or a rendered graph when the optional graphviz package is installed.

## Install
`git clone https://github.com/ShadowGuard-AI/threatmod-threatreportgenerator.git`

## Usage
`python3 main.py -i input.json -o threat_report -f markdown`

Running the tool writes only the report file you name (and a graph PNG when graphviz rendering succeeds). It does not create any other files. To write a small example input file, run `python3 main.py --example`, which writes example_data.json and exits.

An empty input object, or input with no components, data flows, or threats, is rejected: the run exits non-zero and no success report is written. The same rejection applies to malformed entries: each component and threat entry must define a name, and each data flow entry must define a source, a destination, and a description.

## Parameters
- `-h`: Show help message and exit
- `-i`: Path to the input data file (JSON only)
- `-o`: Name of the output file (without extension)
- `-f`: Format of the report (markdown)
- `-d`: Include a diagram in the report (uses graphviz when installed)
- `--no-diagram`: Exclude a diagram in the report
- `--example`: Write example_data.json in the working directory and exit

## License
MIT License. See LICENSE.
