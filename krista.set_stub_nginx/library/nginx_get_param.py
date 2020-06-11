#!/usr/bin/env python
# -*- coding: utf-8 -*-

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: nginx_get_param

short_description: Модуль для получения параметров от nginx по
server_name

version_added: "2.4"

description:
    - "Принимает как обязательный параметр server_name и возвращает:
        conf_path - путь до конфига,
        listen - содержимое параметра listen, пока подразумевается один
         параметр на server
        upd_location - булево значение, наличие location для target
         server, если есть то true, иначе false
        upd_addr - содержит IP адрес target server
        upd_port - содержит порт target server"
        new_upd_location - булево значение, наличие location для нового target
        new_upd_addr - содержит IP адрес нового target server
        new_upd_port - содержит порт нового target server

options:
    server_name:
        description:
            - fqdn имя веб ресурса для которого ищутся параметры
        required: true

author:
    - Дмитрий Храпов (@hrapovd)
'''

EXAMPLES = '''
'''

RETURN = '''
servers:
    description: список параметров, conf_path, 1 или более server
    returned: always
    type: dict
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
        {"file_name": "File's lines are one string",
         "file_name2": "File2's lines are one string"}
    а также с удалением пустых строк и комментариев, возвращает тип
    dict
    """
    curr_name = ''
    config = dict()
    out_conf = dict()
    serv_sections = dict()
    file_name = re.compile("#\sconfiguration\sfile.*\:", re.I)
    empty_line = re.compile("^\s*$")
    comment = re.compile("#.*$")
    server_key = re.compile("(^|;|\})server\s*\{")
    for line in in_list:
        if file_name.search(line):
            name = str(line.split()[3].strip(':'))
            curr_name = name
            config[name] = ""
        if curr_name == '':
            continue
        elif empty_line.search(line):
            continue
        elif comment.search(line):
            tmp_str = ""
            for curr_char in line:
                if curr_char == '#':
                    config[curr_name] = config[curr_name] + tmp_str.strip()
                    continue
                tmp_str = tmp_str + curr_char
            continue
        else:
            config[curr_name] = config[curr_name] + line.strip()
    for key in config:
        if server_key.search(config[key]):
            out_conf[key] = config[key]
    return out_conf

def main():
    module = AnsibleModule(
        argument_spec=dict(
            server_name=dict(required=True, type='str')),
        supports_check_mode=True
    )

    server_name = module.params['server_name']

    if module.check_mode:
        servers = {"server_name": server_name}
        return servers

    module.warnings = []

    try:
        nginx_servs_confs = _conf_to_dict(_get_conf_nginx(module))
    except:
        module.exit_json(changed=False, servers="Ошибка при вызове nginx")
        module.fail_json(msg="Произошла ошибка, при попытке получения конфигурации \
                                nginx")

    module.exit_json(changed=False, servers=_parse_config(nginx_servs_confs, server_name))
#    module.exit_json(changed=False, servers=_get_conf_nginx(module))

if __name__ == '__main__':
    main()
