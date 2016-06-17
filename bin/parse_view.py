#!/usr/bin/python

import sys
import os.path
import pickle

from dinosaurus_lib.dnsdatabase  import DnsDatabaseFile,DnsDatabasePickled
from dinosaurus_lib.output_views import HtmlLocalView,ConfView,IpListView,HtmlView,HtmlPage
from dinosaurus_lib.labelers     import ListLabeler,DictMultipleLabeler

from dinosaurus_lib.filter import FilterCascade,NormalizeSOA,MapViews

PRIMARY_MASTER="rvvmdns03pl.server.intra.rve." 
EMAIL_ADMIN="nsmaster.regione.veneto.it."

f_dati=sys.argv[1]
out_dir=sys.argv[2]
netscan_dir=sys.argv[3]
vlans_dir=sys.argv[4]
f_datiweb=sys.argv[5]

input_basename=os.path.basename(f_dati)

f_vlans=vlans_dir+"/vlans.csv"
f_ping_ok=netscan_dir+"/ping_ok"
f_ping_errors=netscan_dir+"/ping_errors"

elab_desc={}

vlan_list=[]
fd=open(f_vlans,"r")
for r in fd.readlines():
    t=r.strip().split(":")
    d={
        "net": t[0],
        "netmask": t[1],
        "vlan_id": t[2],
        "vlan_desc": t[3],
        "vlan_location": "",
        "vlan_address": "",
        "vlan_dubbio": "",
        "vlan_competenza": "",
        "vlan_note": "",
        "vlan_tabella": ""
        }

    aggiuntivi= [ "vlan_location",
                  "vlan_address",
                  "vlan_dubbio",
                  "vlan_competenza",
                  "vlan_note",
                  "vlan_tabella" ]

    for n in range(0,len(aggiuntivi)):
        if len(t)>4+n:
            d[aggiuntivi[n]]=t[n+4]
    if not d["vlan_id"]: d["vlan_id"]="="
    if not d["netmask"]: d["netmask"]=24
    else: d["netmask"]=int(d["netmask"])
    if not d["vlan_desc"]: 
        if d["vlan_id"] and d["vlan_id"]!="=":
            d["vlan_desc"]="vlan "+str(d["vlan_id"])
    vlan_list.append(d)
fd.close()

class PingMap(object):
    def __init__(self,f_ping_ok,f_ping_errors):
        self._map={}
        if os.path.exists(f_ping_ok):
            fd=open(f_ping_ok,"r")
            for r in fd.readlines():
                self._map[r.strip()]="ok"
            fd.close()
        if os.path.exists(f_ping_errors):
            fd=open(f_ping_errors,"r")
            for r in fd.readlines():
                self._map[r.strip()]="errors"
            fd.close()

    def __call__(self,ip):
        if self._map.has_key(ip):
            return self._map[ip]
        return ""
    
ping_map=PingMap(f_ping_ok,f_ping_errors)

class LabelerGroup(object):
    def __init__(self,out_dir,netscan_dir,f_datiweb):
        self.out_dir=out_dir
        self.netscan_dir=netscan_dir
        self.f_datiweb=f_datiweb
        self.ping_ok=[]
        self.ping_errors=[]
        self.nmap_os={}
        self.cmdb_ip={}
        self.cmdb_host={}
        self.win_dynamic={}
        self.datiweb={}

    def _load_ping(self):
        if os.path.exists(self.netscan_dir+"/ping_ok"):
            fd=open(self.netscan_dir+"/ping_ok","r")
            for r in fd.readlines():
                self.ping_ok.append(r.strip())
            fd.close()
        if os.path.exists(self.netscan_dir+"/ping_errors"):
            fd=open(self.netscan_dir+"/ping_errors","r")
            for r in fd.readlines():
                self.ping_errors.append(r.strip())
            fd.close()

    def _load_datiweb(self): 
        if not os.path.exists(self.f_datiweb):
            return
        datiweb={}
        fd=open(self.f_datiweb,"r")
        for r in fd.readlines():
            t=r.strip().split(":")
            name=t[0].lower()
            name_type=t[1].lower()
            host=t[2].lower()
            fconf=t[3].lower()
            vh_ip=t[4].lower()
            vh_port=t[5].lower()
            if not datiweb.has_key(name):
                datiweb[name]={"host": [], "type": [] }
            datiweb[name]["host"].append(host)
            datiweb[name]["type"].append(name_type)
        fd.close()
        for name,D in datiweb.items():
            D["type"]=list(set(D["type"]))
            if len(D["type"]) > 1:
                style_cell="red"
            else:
                style_cell="green"
            self.datiweb[name]=( [", ".join(D["host"]),", ".join(D["type"])],"",style_cell )

    def _load_cmdb(self):
        if not os.path.exists(self.out_dir+"/cmdb.csv"):
            return
        self.cmdb_ip={}
        self.cmdb_host={}
        fd=open(self.out_dir+"/cmdb.csv","r")
        for r in fd.readlines():
            t=r.strip().split(";")
            host=t[0].lower()
            ip=t[1]
            desc=";".join(t[2:])
            self.cmdb_ip[ip]=( [host,desc],"","green" )
            self.cmdb_host[host]=( [ip,desc],"","green" )
        fd.close()

    def _load_nmap(self):
        if not os.path.exists(self.netscan_dir+"/nmap_os"):
            return
        fd=open(self.netscan_dir+"/nmap_os","r")
        temp={}
        for r in fd.readlines():
            t=r.strip().split(" ")
            if len(t)==2: continue
            ip=t[0]
            key=t[1]
            val=" ".join(t[2:])
            if not temp.has_key(ip):
                temp[ip]={}
            temp[ip][key]=val
        fd.close()
        
        self.nmap_os={}
        for ip,v_dict in temp.items():
            if v_dict.has_key("os_details"):
                opersys=v_dict["os_details"]
                if v_dict.has_key("os_aggressive"):
                    opersys+=" ("+v_dict["os_aggressive"]+")"
            elif v_dict.has_key("os_aggressive"):
                opersys=v_dict["os_aggressive"]
            elif v_dict.has_key("running"):
                opersys=v_dict["running"]
            else:
                opersys=""
            if v_dict.has_key("partial_match"):
                partial_match=v_dict["partial_match"]
            else:
                partial_match=""
            if v_dict.has_key("aggressive"):
                aggressive=v_dict["aggressive"]
            else:
                aggressive=""
            if v_dict.has_key("device_type"):
                device_type=v_dict["device_type"]
            else:
                device_type=""
            if opersys+partial_match+aggressive+device_type=="":
                continue
            if not partial_match and not aggressive: 
                flag="OK"
            elif not aggressive: 
                flag="part."
            else:
                flag="aggr."
            if flag=="OK":
                style_cell="green"
            else:
                style_cell="yellow"
            self.nmap_os[ip]=( [opersys,device_type,flag],"",style_cell )

    def _load_win_dynamic(self):
        if not os.path.exists(self.out_dir+"/win_dynamic.csv"):
            return
        fd=open(self.out_dir+"/win_dynamic.csv","r")
        self.win_dynamic_name={}
        self.win_dynamic_ip={}
        for r in fd.readlines():
            t=r.strip().split(" ")
            owner=t[0]
            rectype=t[-2]
            val=t[-1]
            
            if rectype=="A":
                self.win_dynamic_name[owner]=( [rectype,val],"","red" )
                self.win_dynamic_ip[val]=( [rectype,owner],"","red" )
            elif rectype=="CNAME":
                self.win_dynamic_name[owner]=( [rectype,val],"","red" )
            else:
                ot=owner.split(".")
                ot=ot[:4]
                ot.reverse()
                ip=".".join(ot)
                self.win_dynamic_ip[ip]=( [rectype,val],"","red" )
                self.win_dynamic_name[val]=( [rectype,ip],"","red" )

        fd.close()

    def _load_win_static(self):
        if not os.path.exists(self.out_dir+"/win_static.csv"):
            return
        fd=open(self.out_dir+"/win_static.csv","r")
        self.win_static_name={}
        self.win_static_ip={}
        for r in fd.readlines():
            t=r.strip().split(" ")
            owner=t[0].lower()
            rectype=t[1]
            val=" ".join(t[2:])
            val=val.lower()
            
            if rectype=="A":
                self.win_static_name[owner]=( [rectype,val],"","yellow" )
                self.win_static_ip[val]=( [rectype,owner],"","yellow" )
            elif rectype=="CNAME":
                self.win_static_name[owner]=( [rectype,val],"","yellow" )
            else:
                ot=owner.split(".")
                ot=ot[:4]
                ot.reverse()
                ip=".".join(ot)
                self.win_static_ip[ip]=( [rectype,val],"","yellow" )
                self.win_static_name[val]=( [rectype,ip],"","yellow" )

        fd.close()


    def load(self):
        self._load_ping()
        self._load_nmap()
        self._load_cmdb()
        self._load_win_dynamic()
        #self._load_win_static()
        #self._load_datiweb()

    def _ping_labeler(self):
        if not self.ping_ok+self.ping_errors: return None
        def data_callable(row): return row.ip
        return ListLabeler("ping",
                           [ ("ok","green","green",self.ping_ok),
                             ("errors","blue","blue",self.ping_errors) ],
                           data_callable,no_label="no")

    def _nmap_labeler(self): 
        if not self.nmap_os: return None
        def data_callable(row): return row.ip
        return DictMultipleLabeler("netscan",["os","device type","quality"],
                                   self.nmap_os,data_callable,no_label="")

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

    def _datiweb_labeler(self): 
        if not self.cmdb_host: return None
        def data_callable(row): return row.name.strip().strip(".")
        return DictMultipleLabeler("virtual host",["server","type"],
                                   self.datiweb,data_callable,no_label="")

    def _win_dynamic_labeler(self): 
        if not self.win_dynamic_ip: return None
        def data_callable(row): return row.ip
        return DictMultipleLabeler("win_dynamic",["type","name"],
                                   self.win_dynamic_ip,data_callable,no_label="")

    def _win_static_labeler(self): 
        if not self.win_static_ip: return None
        def data_callable(row): return row.ip
        return DictMultipleLabeler("win_static",["type","name"],
                                   self.win_static_ip,data_callable,no_label="")

    def _win_static_name_labeler(self): 
        if not self.win_static_ip: return None
        def data_callable(row): 
            print row.name.strip().strip(".").lower()
            return row.name.strip().strip(".").lower()
        return DictMultipleLabeler("win_static",["type","name"],
                                   self.win_static_name,data_callable,no_label="")

    def labelers_ip(self):
        ret=[]
        for lab in [ self._ping_labeler(),#self._win_static_labeler(),
                     self._win_dynamic_labeler(),self._cmdb_labeler(),self._nmap_labeler() ]:
            if not lab: continue
            ret.append(lab)
        return ret

    def labelers_name(self):
        ret=[]
        # #for lab in [ self._cmdb_host_labeler() ]:
        # for lab in [ self._win_static_name_labeler(),self._datiweb_labeler() ]:
        #     if not lab: continue
        #     ret.append(lab)
        return ret

class Elaboration(object):
    def __init__(self,out_dir,label,title,view_params,vlan_list,ping_map):
        self.out_dir=out_dir
        self.label=label
        self.title=title
        self.view_params=view_params
        self.dir_conf=out_dir+"/"+label+"_conf"
        self.dir_local_html=out_dir+"/"+label+"_local_html"
        self.dir_html=out_dir+"/"+label+"_html"
        self.context="/"+label+"_html"
        self.dir_local_static=out_dir+"/static_local"
        self.dir_static=out_dir+"/static"
        self.docs_root_local="/home/dragut/dragut-2.0/share/admin_script_sources/dns-regione/docs"
        self.docs_root="/dns-docs"
        self.static_root="/static"
        self.ip_list_csv=out_dir+"/ip_list_"+label+".csv"
        self.pickle_fname=out_dir+"/"+input_basename+"_"+label+".pickle"
        self.vlan_list=vlan_list
        self.ping_map=ping_map
        self.db=None

    def build(self):
        pass

    def load(self): 
        if os.path.exists(self.pickle_fname):
            print "Load from pickle "+self.label
            fd=open(self.pickle_fname,"r")
            self.db=pickle.load(fd)
            fd.close()
        else:
            self.build()
            fd=open(self.pickle_fname,'w')
            pickle.dump(self.db,fd,pickle.HIGHEST_PROTOCOL)
            fd.close()

class ElaborationFile(Elaboration):
    def __init__(self,out_dir,label,title,view_params,vlan_list,ping_map,fname):
        Elaboration.__init__(self,out_dir,label,title,view_params,vlan_list,ping_map)
        self.fname=fname
    
    def build(self):
        self.db=DnsDatabaseFile(self.fname,self.title)

class ElaborationFilter(Elaboration):
    def __init__(self,out_dir,label,title,view_params,vlan_list,ping_map,current_db,dns_filter):
        Elaboration.__init__(self,out_dir,label,title,view_params,vlan_list,ping_map)
        self.filter=dns_filter
        self.current_db=current_db

    def build(self):
        self.db=self.filter(self.current_db,self.title)

elab_desc=[ ElaborationFile(out_dir,"current","Configurazione corrente",
                            { "windows": { "order": 10 },
                              "collaudo":{ "order": 15 },
                              "intra":   { "order": 20 },
                              "extra":   { "order": 30 },
                              "guest":   { "order": 40 },
                              "any":     { "order": 50 },
                              },        
                            vlan_list,ping_map,
                            f_dati) ]

elab_desc[0].load()

dns_filter=FilterCascade(NormalizeSOA(PRIMARY_MASTER,EMAIL_ADMIN),
                         MapViews( [ ("windows","private_intranet"),
                                     ("collaudo","private_collaudo"),
                                     ("intra","private_intranet"),
                                     ("any",  "public_internet"),
                                     ("guest","public_guest"),
                                     ("extra","public_extranet") ] ))

elab_desc.append(ElaborationFilter(out_dir,"new","Configurazione target",
                                   { "private_intranet": { "order":  10 },
                                     "private_collaudo": { "order":  20 },
                                     "public_extranet":  { "order":  50 },
                                     "public_guest":     { "order": 100 },
                                     "public_internet":  { "order": 150 },
                                     },vlan_list,ping_map,
                                   elab_desc[0].db,dns_filter))
elab_desc[1].load()

out_views=[ 
    HtmlLocalView,
    ConfView,
    IpListView
    ]

menus_local={ "single_db": [],
              "main": [ ("file:///"+out_dir+"/index_local.html","Home") ] }
menus={ "single_db": [],
        "main": [ ("/","Home") ] }

for elab in elab_desc:
    menus["main"].append( (elab.context,elab.db.name) )
    menus_local["main"].append( ("file:///"+elab.dir_local_html+"/index.html",elab.db.name) )
    
menus["main"].append( ("/old_html","Pre pulizie") )
menus_local["main"].append( ("file:///"+out_dir+"/old_local_html/index.html","Pre pulizie") )

menus["main"].append( (elab.docs_root,"Documentation") )
menus_local["main"].append( ("file:///"+elab.docs_root_local+"/index.html","Documentation") )

index_local=HtmlPage("index_local.html","Indice Principale",out_dir,"file:///"+out_dir,"file:///"+out_dir+"/static",
                     menus_local,"Indice Principale")
index=HtmlPage("index.html","Indice Principale",out_dir,"/","/static",
               menus,"Indice Principale")

for f in [index_local,index]:
    f.open()
    f.write("<ul>\n")

for elab in elab_desc:
    index.write('<li><a href="'+elab.context+'">'+elab.db.name+'</a></li>\n')
    index_local.write('<li><a href="file:///'+elab.dir_local_html+'/index.html">'+elab.db.name+'</a></li>\n')

index.write('<li><a href="/old_html">Pre pulizie</a></li>\n')
index_local.write('<li><a href="file:///"+out_dir+"/old_local_html/index.html">Pre pulizie</a></li>\n')

index.write('<li><a href="'+elab.docs_root+'">Documentazione</a></li>\n')
index_local.write('<li><a href="file:///'+elab.docs_root_local+'/index.html">Documentazione</a></li>\n')

for f in [index_local,index]:
    f.write("</ul>\n")
    f.close()

labeler_group=LabelerGroup(out_dir,netscan_dir,f_datiweb)
labeler_group.load()
labelers={ "ip": labeler_group.labelers_ip(),
           "name": labeler_group.labelers_name() }

for elab in elab_desc:
    print elab.dir_html
    out_views=[ 
        HtmlLocalView(elab.dir_local_html,elab.dir_local_static,menus_local,elab.vlan_list,elab.ping_map,labelers=labelers),
        HtmlView(elab.dir_html,elab.context,elab.dir_static,elab.static_root,menus,elab.vlan_list,elab.ping_map,labelers=labelers),
        ConfView(elab.dir_conf,elab.view_params),
        #IpListView(elab.ip_list_csv)
        ]
    for oview in out_views:
        oview.output(elab.db)
    


