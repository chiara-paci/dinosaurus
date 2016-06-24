#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import os.path
import pickle

import dinosaurus_lib.dnsdatabase as dns_database
import dinosaurus_lib.elaborations as dns_elaborations
import dinosaurus_lib.tcpip as dns_tcpip

from dinosaurus_lib.labelers     import ListLabeler,DictMultipleLabeler

from dinosaurus_lib.filter import FilterCascade,NormalizeSOA,MapViews



PRIMARY_MASTER="rvvmdns03pl.server.intra.rve." 
EMAIL_ADMIN="nsmaster.regione.veneto.it."

f_dati=sys.argv[1]
f_vlans=sys.argv[2]
f_cmdb=sys.argv[3]
templates_dir=sys.argv[4]
out_dir=sys.argv[5]
out_label=sys.argv[6]

vlan_manager=dns_tcpip.VLanManager(f_vlans,        
                                   competenza_map={ u"reti": u"#c0ffd0", 
                                                    u"eng": u"#e0e0e0", 
                                                    u"sanità": u"#ffd0b0", 
                                                    u"ibm": u"#b0d0ff" })

class LabelerGroup(object):
    def __init__(self,out_dir,f_cmdb):
        self.out_dir=out_dir
        self.f_cmdb=f_cmdb
        self.cmdb_ip={}
        self.cmdb_host={}

    def _load_cmdb(self):
        if not os.path.exists(self.f_cmdb):
            return
        self.cmdb_ip={}
        self.cmdb_host={}
        fd=open(self.f_cmdb,"r")
        for r in fd.readlines():
            t=r.strip().split(";")
            host=t[0].lower()
            ip=t[1]
            desc=";".join(t[2:])
            self.cmdb_ip[ip]=( [host,desc],"","green" )
            self.cmdb_host[host]=( [ip,desc],"","green" )
        fd.close()

    def load(self):
        self._load_cmdb()

    def _cmdb_labeler(self): 
        if not self.cmdb_ip: return None
        def data_callable(row): return row.ip
        return DictMultipleLabeler("cmdb",["host","description"],
                                   self.cmdb_ip,data_callable,no_label="")

    def _cmdb_host_labeler(self): 
        if not self.cmdb_host: return None
        def data_callable(row): return row.name.strip().strip(".")
        return DictMultipleLabeler("cmdb",["ip","description"],
                                   self.cmdb_host,data_callable,no_label="")


    def labelers_ip(self):
        ret=[]
        for lab in [ self._cmdb_labeler() ]:
            if not lab: continue
            ret.append(lab)
        return ret

    def labelers_name(self):
        ret=[]
        # for lab in [ self._cmdb_host_labeler() ]:
        #     if not lab: continue
        #     ret.append(lab)
        return ret

labeler_group=LabelerGroup(out_dir,f_cmdb)
labeler_group.load()
labelers={ "ip": labeler_group.labelers_ip(),
           "name": labeler_group.labelers_name() }

old_elab=dns_elaborations.ElaborationFile(out_dir,out_label,"Configurazione corrente",
                                          { "windows": { "order": 10 },
                                            "collaudo":{ "order": 15 },
                                            "intra":   { "order": 20 },
                                            "extra":   { "order": 30 },
                                            "guest":   { "order": 40 },
                                            "any":     { "order": 50 }, },        
                                          f_dati)

old_elab.load()

# dns_filter=FilterCascade(NormalizeSOA(PRIMARY_MASTER,EMAIL_ADMIN),
#                          MapViews( [ ("windows","private_intranet"),
#                                      ("collaudo","private_collaudo"),
#                                      ("intra","private_intranet"),
#                                      ("any",  "public_internet"),
#                                      ("guest","public_guest"),
#                                      ("extra","public_extranet") ] ))

# new_elab=dns_elaborations.ElaborationFilter(out_dir,"new_"+out_label,"Configurazione target",
#                                             { "private_intranet": { "order":  10 },
#                                               "private_collaudo": { "order":  20 },
#                                               "public_extranet":  { "order":  50 },
#                                               "public_guest":     { "order": 100 },
#                                               "public_internet":  { "order": 150 }, },
#                                             old_elab.db,dns_filter)
# new_elab.load()

##### Output


old_elab.html_local_view(vlan_manager,labelers=labelers)
# old_elab.html_view(vlan_manager,labelers=labelers)
# old_elab.conf_view()

# new_elab.conf_view()
# new_elab.cmd_view()

