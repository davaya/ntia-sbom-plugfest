import jadn
import json
import os
import shutil
from collections import defaultdict
from typing import NoReturn


sbom_folder = 'Plugfest #1 20210409'

# Map sbom format to name of schema file to use
schema_filename = {
    'spdx': 'spdx-reverse'
}


def check_sbom(file: str, sbom_format: str, file_format: str) -> dict:
    print(f'{file} ({sbom_format}, {file_format})')
    schema_file = os.path.join('Out', schema_filename[sbom_format.strip().lower()] + '.jadn')
    try:
        schema = jadn.load(schema_file)
    except FileNotFoundError:
        raise ValueError(f'No {sbom_format} schema')
    codec = jadn.codec.Codec(schema, verbose_rec=True, verbose_str=True)
    with open(os.path.join(sbom_folder, file), encoding='utf-8') as fd:
        sbdoc = json.load(fd)   # TODO: JADN Codec needs to decode from file, not Python object
        sbdoc_decoded = codec.decode('Document', sbdoc)
        # assert sbdoc == sbdoc_decoded // TODO: check list reordering
    return sbdoc


def translate(filename: str, odir: str) -> NoReturn:
    fn, ext = os.path.splitext(filename)
    try:
        loader = {
            '.jadn': jadn.load,
            '.jidl': jadn.convert.jidl_load,
            '.html': jadn.convert.html_load
        }[ext]
    except KeyError:
        print(f'Unsupported schema format: {filename}')
        return

    print(f'{filename:}:')
    schema = loader(os.path.join('Schema', filename))
    print('\n'.join([f'{k:>15}: {v}' for k, v in jadn.analyze(jadn.check(schema)).items()]))

    jadn.convert.dot_dump(schema, os.path.join(odir, fn + '.dot'), style={'links': True})
    cols = {'name': 24,'desc': 56}    # Specify type column and description length to truncate
    jadn.convert.jidl_dump(schema, os.path.join(odir, fn + '.jidl'), style=cols)
    jadn.convert.jidl_dump(jadn.transform.strip_comments(schema), os.path.join(odir, fn + '_s.jidl'), style={'name': 24})
    jadn.convert.html_dump(schema, os.path.join(odir, fn + '.html'))
    jadn.convert.table_dump(schema, os.path.join(odir, fn + '.md'))
    jadn.convert.proto_dump(schema, os.path.join(odir, fn + '.proto'))
    jadn.translate.json_schema_dump(schema, os.path.join(odir, fn + '.json'))
    jadn.dump(schema, os.path.join(odir, fn + '.jadn'))
    jadn.dump(jadn.transform.simplify(jadn.transform.strip_comments(schema)),
              os.path.join(odir, fn + '_core.jadn'))


if __name__ == '__main__':
    print(f'Using JADN version {jadn.__version__}\n')

    # Validate schema and translate to other formats
    output_dir = 'Out'
    css_dir = os.path.join(output_dir, 'css')
    os.makedirs(css_dir, exist_ok=True)
    shutil.copy(os.path.join(jadn.data_dir(), 'dtheme.css'), css_dir)
    for f in os.listdir('Schema'):
        translate(f, output_dir)

    # Get list of SBOM files to analyze from Plugfest folder
    print()
    with open(os.path.join(sbom_folder, 'sbom_files.txt')) as f:
        for line in f.readlines():
            if not line.strip().startswith('#') and len(x := line.split(',')) == 3:

                # Validate SBOM file against schema
                file = os.path.join(*x[0].split('/'))
                try:
                    doc = check_sbom(file, sbom_fmt:=x[1].strip(), file_fmt:=x[2].strip())
                except ValueError as e:
                    print(f' ERR: {e}')

                # Analyze SBOM data to identify which link associations are used
                if 'doc' in locals() and sbom_fmt == 'spdx':
                    rels = defaultdict(list)
                    for rel in doc['relationships']:
                        rels[rel['spdxElementId']].append((rel['relationshipType'], rel['relatedSpdxElement']))
                    print(f'  {len(rels)} relationship sources')

