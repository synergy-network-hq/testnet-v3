"""Export the native configuration field schema from canonical Rust declarations.

Native preflight remains responsible for semantic and authenticated-network
validation. No second set of consensus defaults is introduced by this exporter.
"""
import json
from pathlib import Path
import re


def generate(source):
    declarations={}
    for path in (Path(source)/'crates/synergy-config/src').glob('*.rs'):
        if path.name.startswith('._'): continue
        text=path.read_text()
        for match in re.finditer(r'pub struct (\w+)\s*\{(.*?)\n\}',text,re.S):
            declarations[match[1]]=re.findall(r'pub (\w+): ([^,\n]+),',match[2])
    def native_type(value):
        if value.startswith('Option<'):
            schema=native_type(value[7:-1]);schema['type']=[schema['type'],'null'];return schema
        if value.startswith('Vec<'):return {'type':'array','items':native_type(value[4:-1])}
        if value in declarations:return structure(value)
        if value=='bool':return {'type':'boolean'}
        if value in ('usize','u16','u32','u64'):return {'type':'integer'}
        return {'type':'string'}
    def structure(name):
        return {'type':'object','additionalProperties':False,
                'properties':{field:native_type(kind) for field,kind in declarations[name]}}
    schema=structure('NodeConfiguration')
    schema.update({'$schema':'https://json-schema.org/draft/2020-12/schema',
                   '$id':'https://schemas.synergy.network/node-config/v1',
                   'title':'Canonical native NodeConfiguration',
                   'required':['schema_version','node_name','role','chain_id','network_id','manifest_path',
                               'public_identity_path','admin_socket_path','storage']})
    schema['properties']['schema_version']['const']=1
    return schema

if __name__=='__main__':
    source=Path(__file__).resolve().parents[2]
    print(json.dumps(generate(source),indent=2,sort_keys=True))
