# threatmod-ThreatReportGenerator
Generates customizable threat model reports in various formats (e.g., Markdown, PDF) from structured threat data (e.g., JSON, YAML).  Leverages Jinja2 for templating and supports inclusion of diagrams and tables. Simplifies documentation and sharing of threat model findings. - Focused on Provides a lightweight framework for creating and visualizing threat models.  Allows users to define system components, data flows, and potential threats.  Generates graphical representations of the threat model and reports on identified risks. The `graphviz` dependency is optional for visualization; if not installed, a text-based output will be used.

## Install
`git clone https://github.com/ShadowStrikeHQ/threatmod-threatreportgenerator`

## Usage
`./threatmod-threatreportgenerator [params]`

## Parameters
- `-h`: Show help message and exit
- `-i`: No description provided
- `-o`: No description provided
- `-f`: No description provided
- `-d`: No description provided
- `--no-diagram`: Exclude a diagram in the report

## License
Copyright (c) ShadowStrikeHQ
