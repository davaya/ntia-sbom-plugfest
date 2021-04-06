import jadn
import json
import os
import shutil
from collections import defaultdict
from typing import NoReturn


sbom_folder = 'Plugfest #1 20210409'


def check_sbom(file: str, sbom_format: str, file_format: str) -> dict:
    print(f'{file} ({sbom_format}, {file_format})')
    schema_file = os.path.join('Out', sbom_format.strip().lower() + '.jadn')
    try:
        schema = jadn.load(schema_file)
    except FileNotFoundError:
        raise ValueError(f'No {sbom_format} schema')
    codec = jadn.codec.Codec(schema, verbose_rec=True, verbose_str=True)
    with open(os.path.join(sbom_folder, file), encoding='utf-8') as fd:
        sbdoc = json.load(fd)   # TODO: JADN Codec needs to decode from file, not Python object
        sbdoc_decoded = codec.decode('Document', sbdoc)
        assert sbdoc == sbdoc_decoded
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
    cols = {'desc': 50, 'page': 120}    # specify comment position and page width to truncate
    jadn.convert.jidl_dump(schema, os.path.join(odir, fn + '.jidl'), style=cols)
    jadn.convert.html_dump(schema, os.path.join(odir, fn + '.html'))
    jadn.convert.table_dump(schema, os.path.join(odir, fn + '.md'))
    jadn.translate.json_schema_dump(schema, os.path.join(odir, fn + '.json'))
    jadn.dump(schema, os.path.join(odir, fn + '.jadn'))
    jadn.dump(jadn.transform.simplify(jadn.transform.strip_comments(schema)),
              os.path.join(odir, fn + '_core.jadn'))


if __name__ == '__main__':
    print(f'Installed JADN version: {jadn.__version__}\n')
    output_dir = 'Out'
    css_dir = os.path.join(output_dir, 'css')
    os.makedirs(css_dir, exist_ok=True)
    shutil.copy(os.path.join(jadn.data_dir(), 'dtheme.css'), css_dir)
    for f in os.listdir('Schema'):
        translate(f, output_dir)

    print()
    with open(os.path.join(sbom_folder, 'sbom_files.txt')) as f:
        for line in f.readlines():
            if not line.startswith('#') and len(x := line.split(',')) == 3:
                file = os.path.join(*x[0].split('/'))
                try:
                    doc = check_sbom(file, sbom_f:=x[1].strip(), file_f:=x[2].strip())
                except ValueError as e:
                    raise
                    # print(f' ERR: {e}')
                # Analyze SBOM data
                if sbom_f == 'spdx':
                    rels = defaultdict(list)
                    for rel in doc['relationships']:
                        rels[rel['spdxElementId']].append((rel['relationshipType'], rel['relatedSpdxElement']))
                    print(f'{len(rels)} elements have relationships')

    # check_sbom(os.path.join('Cybeats', 'time.sbom.json'), 'SPDX')
