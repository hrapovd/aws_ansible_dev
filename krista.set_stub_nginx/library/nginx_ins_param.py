#!/usr/bin/env python
# -*- coding: utf-8 -*-

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: nginx_ins_param

short_description: Модуль для внесения параметров в секцию server по
server_name

version_added: "2.4"

description:
    - "Принимает как обязательный параметр server_name и блок параметра(ов) для
    вставки.

options:
    server_name:
        description:
            - fqdn имя веб ресурса для которого ищутся параметры
        required: true
    insert_block:
        description:
            - блок параметра(ов) для вставки.
        required: true

author:
    - Дмитрий Храпов (@hrapovd)
'''

EXAMPLES = '''
'''

RETURN = '''
warnings:
    description: list of warning messages
    returned: when needed
    type: list
rc:
    description: return code of underlying command
    returned: failed
    type: int
stdout:
    description: stdout of underlying command
    returned: failed
    type: string
stderr:
    description: stderr of underlying command
    returned: failed
    type: string
'''

import re
from ansible.module_utils.basic import AnsibleModule

def _get_ctl_binary(module):
    ctl_binary = module.get_bin_path('nginx')
    if ctl_binary is not None:
        return ctl_binary

    module.fail_json(
        msg="nginx not found."
    )

def _get_conf_nginx(module):
    control_binary = _get_ctl_binary(module)
    result, stdout, stderr = module.run_command("%s -T" % control_binary)

    if result != 0:
        error_msg = "Error executing %s: %s" % (control_binary, stderr)
        module.fail_json(msg=error_msg)
    return stdout.splitlines()

def _parse_config(confs_dict, serv_name):
    """
    Функция принимает словарь конфигов nginx, а также искомый fqdn
    и возвращает список заданного формата.
    """
    param = {"server": list(), "conf_path": list()}
    tmp_str = ""
    curr_el = ""
    ssl_block = ""
    include_block = ""
    serv_count = 0
    fqdn_list = serv_name.split(".")
    fqdn = '\.'.join(fqdn_list)
    serv_name_key = re.compile('server_name\s+' + fqdn + '\s*')
    server_key = re.compile("(^|;|\})server\s*")
    ssl_key = re.compile("(^|;|\})ssl\S*\s+\S*")
    include_key = re.compile("(^|;|\})include\s+\S+")
    location_key = re.compile("(^|;|\})location\s+.+\s+\S*")
    for key in confs_dict:
        if serv_name_key.search(confs_dict[key]):
            param["conf_path"].append(key)
            for char in confs_dict[key]:
                if char != ';' and char != '{' and char != '}':
                    tmp_str = tmp_str + char
                elif char == ';':
                    if "server" in curr_el and "listen" in tmp_str:
                        param["server"][serv_count - 1]["listen"].append(" ".join(tmp_str.split()[1:]))
                    elif "server" in curr_el and ssl_key.search(tmp_str):
                        param["server"][serv_count -1]["ssl_options"] = True
                        ssl_block = ssl_block + tmp_str + ";" + "\n"
                        param["server"][serv_count -1]["ssl_block"] = ssl_block
                    elif "server" in curr_el and include_key.search(tmp_str):
                        param["server"][serv_count -1]["include_options"] = True
                        include_block = include_block + tmp_str + ";" + "\n"
                        param["server"][serv_count -1]["include_block"] = include_block
                    elif "location" in curr_el and param["server"][serv_count - 1]["upd_location"]:
                        if "proxy_pass" in tmp_str:
                            ts_addr = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
                            ts_port = re.compile(r"\:(\d{4,5})")
                            param["server"][serv_count - 1]["upd_addr"] = " ".join(ts_addr.findall(" ".join(tmp_str.split()[1:])))
                            param["server"][serv_count - 1]["upd_port"] = " ".join(ts_port.findall(" ".join(tmp_str.split()[1:])))
                    elif "location" in curr_el and param["server"][serv_count - 1]["new_upd_location"]:
                        if "proxy_pass" in tmp_str:
                            ts_addr = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
                            ts_port = re.compile(r"\:(\d{4,5})")
                            param["server"][serv_count - 1]["new_upd_addr"] = " ".join(ts_addr.findall(" ".join(tmp_str.split()[1:])))
                            param["server"][serv_count - 1]["new_upd_port"] = " ".join(ts_port.findall(" ".join(tmp_str.split()[1:])))
                    tmp_str = ""
                elif char == '{':
                    if server_key.search(tmp_str):
                        param["server"].append(dict())
                        curr_el = "server"
                        serv_count = serv_count + 1
                        param["server"][serv_count - 1]["upd_location"] = False
                        param["server"][serv_count - 1]["new_upd_location"] = False
                        param["server"][serv_count - 1]["ssl_options"] = False
                        param["server"][serv_count - 1]["include_options"] = False
                        param["server"][serv_count - 1]["listen"] = list()
                    elif location_key.search(tmp_str):
                        curr_el = "location"
                        if "updatedeploy" in tmp_str:
                            param["server"][serv_count - 1]["upd_location"] = True
                        if "updateclient" in tmp_str:
                            param["server"][serv_count - 1]["new_upd_location"] = True
                    tmp_str = ""
                elif char == '}':
                    tmp_str = ""
    return param

def _conf_to_dict(in_list):
    """
    Функция преобразования входного списка строк в словарь вида:
        {"file_name": [File's lines like list],
         "file_name2": [File's lines like list]}
    возвращает тип dict при этом содержит конфигурации содержащие секцию server.
    """
    curr_name = ''
    config = dict()
    out_conf = dict()
    serv_sections = dict()
    file_name = re.compile("#\sconfiguration\sfile.*\:", re.I)
    server_key = re.compile("(^|;|\})server\s*\{")
    for line in in_list:
        if file_name.search(line):
            name = str(line.split()[3].strip(':'))
            curr_name = name
            config[name] = list()
        if curr_name != '':
            config[curr_name].append(line)
        elif curr_name == '':
            continue
    for key in config:
        for el in config[key]:
            if server_key.search(el):
                out_conf[key] = config[key]
    return out_conf

def _get_config_with_fqdn(in_dict, fqdn):
    '''
    Функция поиска конфига с нужным fqdn.
    Принимает dictionary вида:
        {"file_path": [file content as list],
         "file_path": [file content as list]
        }
    Возвращает dictionary вида, содержащий не закомментированный
    server_name fqdn :
        {"file_path": [file content as list],
         "file_path": [file content as list]
        }
    '''
    out_dict = dict()
    fqdn_list = serv_name.split(".")
    fqdn = '\.'.join(fqdn_list)
    serv_name_key = re.compile('server_name\s+' + fqdn + '\s*')
    for key in in_dict:
        if serv_name_key.search(in_dict[key]):


def _insert_block(confs_dict, block_to_insert):
    '''
    Функция вставки блока в блок server конфига.
    Ожидает dictionary вида:
        {"file_name": [File's lines like list],
         "file_name2": [File's lines like list]}
    и строку для вставки. И возвращает dictionary вида со вставленным блоком:
        {"file_name": [File's lines like list],
         "file_name2": [File's lines like list]}
    '''
    curr_block = list()
    out_conf = dict()
    server_key = re.compile("(^|;|\})server\s*\{")
    for conf in confs_dict:
        out_conf[conf]=list()
        for line in confs_dict[conf]:
            if server_key.search(line):
                out_conf[key] = config[key]
    return out_conf

def main():
    from datetime import datetime
    from shutil import copy
    module = AnsibleModule(
        argument_spec=dict(
            server_name=dict(required=True, type='str'),
            insert_block=dict(required=True, type='str'))
        supports_check_mode=True
    )

    server_name = module.params['server_name']
    insert_block = module.params['insert_block']

    if module.check_mode:
        servers = {"server_name": server_name}
        return servers

    module.warnings = []

'''
1. Found config file with fqdn
'''
    try:
        nginx_servs_confs = _conf_to_dict(_get_conf_nginx(module))
    except:
        module.exit_json(changed=False, servers="Ошибка при вызове nginx")
        module.fail_json(msg="Произошла ошибка, при попытке получения конфигурации \
                                nginx")
    new_servs_confs = _insert_block(nginx_servs_confs, insert_block)

'''
2. Backup configuration file befor write in file and write file.
'''
    for config in new_servs_confs:
        new_config = str(config)
        new_config = new_config + '.' + str(datetime.today()).replace(' ','_')
        copy(config,new_config)
        with open(config, 'w') as curr_config:
            curr_config.writelines(new_servs_confs[config])

    module.exit_json(changed=True)
#    module.exit_json(changed=False, servers=_get_conf_nginx(module))

if __name__ == '__main__':
    main()
