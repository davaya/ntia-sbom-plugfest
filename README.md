# Software Bill of Materials (SBOM) Information Modeling Tools

## Prerequisites:
* Python version 3.8 or later
* JSON Abstract Data Notation (JADN) package installed using `pip`

## Operation:
In the Plugfest data folder, edit `sbom_files.txt` to configure which files to validate against an information model.

Edit the script `check_sboms.py` to configure:
1. The name of the Plugfest data folder, e.g., `sbom_folder = 'Plugfest #1 20210409'`
1. The information model to use for each SBOM format, e.g., `schema_filename = {'spdx': 'spdx-reverse'}`

The script will:

1. Create a folder `Out` to contain artifacts generated from the information model(s)

1. For each information model `x` in the `Schema` folder, translate to a set of artifacts
    1. JADN schema `x.jadn` used to validate example data
    1. JSON Schema `x.json` used to validate example data
    1. IDL text file `x.jidl` used to document the IM
    1. Markdown table file `x.md` used to document the IM
    1. HTML table file `x.html` used to document the IM
    1. GraphViz file `x.dot` used to visualize the IM

1. For each SBOM document listed in `sbom_files.txt`, validate the document
against the JADN schema for that SBOM's format.

The `check_sboms` script can be edited to perform whatever additional analysis
is desired on each SBOM document.

The script regenerates all artifacts in the `Out` folder before checking the
SBOM documents, so the information model development cycle is:

1. Edit IM in the `Schema` folder
1. Run `check_sboms.py`
1. Repeat