import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

import networkx as nx

try:
    import graphviz  # Optional dependency for visualization
    HAS_GRAPHVIZ = True
except ImportError:
    HAS_GRAPHVIZ = False
    print("graphviz not found. Visualization will be text-based.")

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

class ThreatReportGenerator:
    """
    Generates threat model reports from structured threat data.
    """

    def __init__(self, data: Dict[str, Any], output_format: str = "markdown", output_file: str = "threat_report", diagram: bool = True) -> None:
        """
        Initializes the ThreatReportGenerator.

        Args:
            data: The threat data as a dictionary.
            output_format: The format of the report (markdown or pdf).
            output_file: The name of the output file (without extension).
            diagram: Flag to include diagram generation.
        """
        self.data = data
        self.output_format = output_format.lower()
        self.output_file = output_file
        self.include_diagram = diagram
        self.graph = nx.DiGraph()  # Initialize a directed graph for visualization
        self.report_content: str = ""


    def _validate_data(self) -> bool:
        """
        Validates the input data.

        Returns:
            True if the data is valid, False otherwise.
        """
        if not isinstance(self.data, dict):
            logging.error("Data must be a dictionary.")
            return False

        # Add more data validation checks as needed based on the expected data structure
        # e.g., check for required keys, data types, etc.

        return True
        

    def generate_graph(self) -> None:
        """
        Generates a directed graph from the threat model data.
        """
        # Assumes a structure where components have names and connections are defined
        if "components" not in self.data or "data_flows" not in self.data:
            logging.warning("Components or data flows not found in data. Skipping graph generation.")
            return

        components = self.data["components"]
        data_flows = self.data["data_flows"]

        for component in components:
            self.graph.add_node(component["name"])

        for flow in data_flows:
            self.graph.add_edge(flow["source"], flow["destination"], label=flow["description"])
    

    def visualize_graph(self) -> str:
         """
         Generates a visualization of the threat model graph.
         """
         if not self.graph.nodes:
             logging.warning("No nodes found in the graph. Skipping visualization.")
             return "No graph data available."
         
         if HAS_GRAPHVIZ:
             dot = graphviz.Digraph(comment='Threat Model')
             for node in self.graph.nodes:
                 dot.node(node)
             for u, v, data in self.graph.edges(data=True):
                 dot.edge(u, v, label=data.get("label", ""))
             
             try:
                 dot.render(filename=f"{self.output_file}_graph", format="png", cleanup=True)  # Saves graph as PNG
                 logging.info(f"Graph saved to {self.output_file}_graph.png")
                 return f"![Threat Model Graph]({self.output_file}_graph.png)"  # Markdown image link
             except graphviz.backend.ExecutableNotFound:
                 logging.error("Graphviz executable not found. Please install graphviz.")
                 return "Graphviz executable not found.  Please install graphviz."
         else:
            text_representation = "Text-based Graph Representation:\n"
            for u, v, data in self.graph.edges(data=True):
                text_representation += f"{u} -> {v} ({data.get('label', '')})\n"
            return text_representation


    def generate_markdown_report(self) -> str:
        """
        Generates a Markdown report from the threat data.

        Returns:
            The Markdown report as a string.
        """
        if not self._validate_data():
            return "Error: Invalid threat data."

        report = f"# Threat Model Report\n\n"
        report += f"**System:** {self.data.get('system_name', 'N/A')}\n\n"
        report += f"**Date Generated:** {self.data.get('date_generated', 'N/A')}\n\n"

        if "components" in self.data:
            report += "## Components\n\n"
            for component in self.data["components"]:
                report += f"### {component['name']}\n"
                report += f"- **Description:** {component.get('description', 'N/A')}\n"
                report += f"- **Type:** {component.get('type', 'N/A')}\n\n"

        if "data_flows" in self.data:
            report += "## Data Flows\n\n"
            report += "| Source | Destination | Description |\n"
            report += "|---|---|---|\n"
            for flow in self.data["data_flows"]:
                report += f"| {flow['source']} | {flow['destination']} | {flow['description']} |\n"
            report += "\n"

        if "threats" in self.data:
            report += "## Threats\n\n"
            for threat in self.data["threats"]:
                report += f"### {threat['name']}\n"
                report += f"- **Description:** {threat.get('description', 'N/A')}\n"
                report += f"- **Likelihood:** {threat.get('likelihood', 'N/A')}\n"
                report += f"- **Impact:** {threat.get('impact', 'N/A')}\n"
                report += f"- **Mitigation:** {threat.get('mitigation', 'N/A')}\n\n"

        if self.include_diagram:
             self.generate_graph()
             graph_visualization = self.visualize_graph()
             report += "## Threat Model Diagram\n\n"
             report += graph_visualization + "\n\n" # include visualization in the report.

        return report


    def generate_report(self) -> None:
        """
        Generates the report based on the specified format.
        """

        if self.output_format == "markdown":
            self.report_content = self.generate_markdown_report()
            file_extension = ".md"
        elif self.output_format == "pdf":
            # Implement PDF generation using a library like WeasyPrint or ReportLab
            logging.error("PDF generation is not implemented yet.")
            print("PDF generation is not implemented yet.")
            return
        else:
            logging.error(f"Unsupported output format: {self.output_format}")
            print(f"Unsupported output format: {self.output_format}")
            return
        
        try:
            with open(self.output_file + file_extension, "w") as f:
                f.write(self.report_content)
            logging.info(f"Report generated successfully: {self.output_file + file_extension}")
            print(f"Report generated successfully: {self.output_file + file_extension}")

        except Exception as e:
            logging.error(f"Error writing report to file: {e}")
            print(f"Error writing report to file: {e}")


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser.

    Returns:
        An argparse.ArgumentParser object.
    """
    parser = argparse.ArgumentParser(
        description="Generates threat model reports from structured threat data."
    )
    parser.add_argument(
        "-i", "--input", required=True, help="Path to the input data file (JSON or YAML)"
    )
    parser.add_argument(
        "-o",
        "--output",
        default="threat_report",
        help="Name of the output file (without extension)",
    )
    parser.add_argument(
        "-f",
        "--format",
        default="markdown",
        choices=["markdown", "pdf"],
        help="Format of the report (markdown or pdf)",
    )
    parser.add_argument(
        "-d",
        "--diagram",
        action="store_true",
        help="Include a diagram in the report (requires graphviz)",
    )
    parser.add_argument(
        "--no-diagram",
        dest="diagram",
        action="store_false",
        help="Exclude a diagram in the report",
    )
    parser.set_defaults(diagram=True) # Diagram generation default is true
    return parser


def load_data(input_file: str) -> Dict[str, Any]:
    """
    Loads data from a JSON or YAML file.

    Args:
        input_file: The path to the input file.

    Returns:
        A dictionary containing the loaded data.
    """
    try:
        with open(input_file, "r") as f:
            if input_file.endswith(".json"):
                data = json.load(f)
            # Add support for YAML if needed:
            # elif input_file.endswith(".yaml") or input_file.endswith(".yml"):
            #     import yaml
            #     data = yaml.safe_load(f)
            else:
                logging.error("Unsupported file format. Only JSON is supported.")
                print("Unsupported file format. Only JSON is supported.")
                sys.exit(1)
        return data
    except FileNotFoundError:
        logging.error(f"Input file not found: {input_file}")
        print(f"Input file not found: {input_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON: {e}")
        print(f"Error decoding JSON: {e}")
        sys.exit(1)
    # Add YAML exception if implementing YAML support.


def main() -> None:
    """
    Main function.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    data = load_data(args.input)

    report_generator = ThreatReportGenerator(
        data, args.format, args.output, args.diagram
    )
    report_generator.generate_report()


if __name__ == "__main__":
    # Example usage (for testing purposes):
    # Create a dummy JSON file
    if not os.path.exists("example_data.json"):
        example_data = {
            "system_name": "Example System",
            "date_generated": "2023-11-15",
            "components": [
                {"name": "Web Server", "description": "Handles HTTP requests", "type": "Server"},
                {"name": "Database", "description": "Stores application data", "type": "Database"},
            ],
            "data_flows": [
                {"source": "Web Server", "destination": "Database", "description": "Queries for user data"},
            ],
            "threats": [
                {
                    "name": "SQL Injection",
                    "description": "Attacker injects malicious SQL code",
                    "likelihood": "High",
                    "impact": "Critical",
                    "mitigation": "Use parameterized queries",
                }
            ],
        }
        with open("example_data.json", "w") as f:
            json.dump(example_data, f, indent=4)

    # To run, execute:
    # python main.py -i example_data.json -o my_threat_report -f markdown
    # or
    # python main.py -i example_data.json -o my_threat_report -f markdown --no-diagram

    main()