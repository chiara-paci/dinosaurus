# -*- coding: utf-8 -*-

import sys,re
import os,datetime
import shutil
import math
import jinja2

import dinosaurus_lib.tcpip as dns_tcpip
import dinosaurus_lib.config as dns_config

from dinosaurus_lib.config import *
from dinosaurus_lib.functions import *
from dinosaurus_lib.dnsdatabase import Zone,Record
from dinosaurus_lib.tables import Table,CellSequence
from dinosaurus_lib.resolutions import ResName,ResIp

class UrlResolver(object):
    """ Container degli url degli oggetti nella documentazione. Callable. """
    def __init__(self):
        self._zone_urls={}
        self._record_urls={}
        self._res_ip_urls={}
        self._res_name_urls={}

    def _get_urls_list(self,obj):
        if isinstance(obj,Zone):
            return self._zone_urls
        if isinstance(obj,Record):
            return self._record_urls
        if isinstance(obj,ResIp):
            return self._res_ip_urls
        if isinstance(obj,ResName):
            return self._res_name_urls
        if isinstance(obj,str):
            t=obj.strip(".").split(".")
            if t[0].isdigit(): 
                return self._res_ip_urls
            return self._res_name_urls
        return None

    def _get_obj_key(self,obj):
        if isinstance(obj,Zone):
            return obj.id
        if isinstance(obj,Record):
            return obj.id
        if isinstance(obj,ResIp):
            return obj.ip.lower()
        if isinstance(obj,ResName):
            return obj.name.lower()
        if isinstance(obj,str):
            return obj.lower()
        return None

    def __call__(self,obj):
        """
        :param obj: un oggetto di tipo Zone, Record, ResIp, ResName o str
        :return: l'url corrispondente all'oggetto

        Se obj è una stringa, tenta di capire se è un ip o un nome e restituisce rispettivamente l'url 
        del ResIp o del ResName corrispondente.

        """
        D=self._get_urls_list(obj)
        if D==None: return "xxx"
        key=self._get_obj_key(obj)
        if not key: return "yyy"
        if D.has_key(key):
            return D[key]
        return "zzz"

    def add_url(self,obj,url):
        """ Aggiunge una coppia oggetto/url. 

        :param obj: un oggetto di tipo Zone, Record, ResIp o ResName
        :param url: l'url corrispondente all'oggetto
        """
        D=self._get_urls_list(obj)
        if D==None: return
        key=self._get_obj_key(obj)
        if not key: return
        D[key]=url

class ZoneOutputMethods(object):
    record_skip=["WINS"]
    record_pass=["MX","NS","A","CNAME","PTR","AAAA","TXT","SPF","HINFO","AFSDB","SRV" ]
    record_rebuild=["SOA"]
    record_format="%-20s %-6.6s %-2.2s %-5.5s"

    def format_zone_header(self,soa_data):
        # @  IN      SOA     ns01.regione.veneto.it. nsmaster.regione.veneto.it.     (
        #         2015062603      ; serial
        #         86400           ; refresh
        #         1800            ; retry
        #         2592000         ; expire
        #         86400                   ); minimum TTL

        T='$TTL '+soa_data["ttl"]+'\n'
        T+=self.record_format % ("@","","","SOA")

        T+=' '+soa_data["primary_master"]+' '+soa_data["email_admin"]+' (\n'

        indent=self.record_format % ("","","","")
        indent+="".join(map(lambda x: " ",range(0,len(soa_data["primary_master"]))))
        indent+=" "

        for val,lab in [ (soa_data["serial_number"],"serial number"),
                         (soa_data["refresh"],      "refresh"),
                         (soa_data["retry"],        "retry"),
                         (soa_data["expiry"],       "expiry"),
                         (soa_data["nx_ttl"],       "nxdomain TTL") ]:
            T+=indent
            T+='%-12s ; %s\n' % (str(val),lab)
        T+=indent
        T+=')\n'
        return T

    def zone_txt_header(self):
        soa_data={
            "primary_master": self.zone.get_primary_master(),
            "email_admin": self.zone.get_email_admin(),
            "serial_number": self.zone.get_serial_number(),
            "ttl": self.zone.get_ttl(),
            "refresh": self.zone.get_refresh(),
            "retry": self.zone.get_retry(),
            "expiry": self.zone.get_expiry(),
            "nx_ttl": self.zone.get_nx_ttl(),
            }

        return self.format_zone_header(soa_data)

    def zone_txt_header_by_view_set(self,view_set):
        soa_data={
            "primary_master": self.zone.get_primary_master_by_view_set(view_set),
            "email_admin": self.zone.get_email_admin_by_view_set(view_set),
            "serial_number": self.zone.get_serial_number_by_view_set(view_set),
            "ttl": self.zone.get_ttl_by_view_set(view_set),
            "refresh": self.zone.get_refresh_by_view_set(view_set),
            "retry": self.zone.get_retry_by_view_set(view_set),
            "expiry": self.zone.get_expiry_by_view_set(view_set),
            "nx_ttl": self.zone.get_nx_ttl_by_view_set(view_set),
            }

        return self.format_zone_header(soa_data)

    def zone_txt_multiple(self):
        T={}
        for view_set in self.zone.merged_views_sets:
            T[view_set]=self.zone_txt_header_by_view_set(view_set)
        for r in self.zone.def_rows+self.zone.rows:
            for view_set,txt in self.record_txt_multiple(r):
                T[view_set]+=txt
        for k in T.keys():
            T[k]+="\n\n"
        return T.items()

    def record_txt_multiple(self,record):
        if record.dns_type.dns_type in self.record_skip: return []
        if record.dns_type.dns_type in self.record_rebuild: return []

        t_format=self.record_format+" %s\n"
        if record.dns_class=="IN": 
            dns_class=""
        else: 
            dns_class=record.dns_class

        T={}
        for view_set,rdata_list in record.merged:
            rec_owner=record.zone.remove_zone_suffix(record.owner)
            if not T.has_key(view_set): T[view_set]=""
            for rdata in rdata_list:
                T[view_set]+=t_format % (rec_owner,
                                         record.zone.normalize_ttl_by_view_set(view_set,rdata.ttl),
                                         dns_class,
                                         record.dns_type.dns_type,
                                         " ".join(rdata.data))
                rec_owner=""
        return T.items()

class PaginationList(list):
    template_row_name="includes/pagination_list_row.html"

    def __init__(self,pagination):
        list.__init__(self)
        self.pagination=pagination

    def title_add(self): return ""

    def __str__(self):
        return str(self[0])+"-"+str(self[-1])

    def known_vlan(self): return False

    def record_link(self,record):
        url=self.pagination.url_resolver(record)
        if not url: return str(record)
        return '<a href="'+url+'">'+str(record)+'</a>'

    def res_link(self,label):
        url=self.pagination.url_resolver(label.lower())
        if not url: 
            return label
        return '<a href="'+url+'">'+label+'</a>'

    def range(self):
        return self.first(),self.last()

    def first(self):
        if self:
            return self[0]
        return None

    def last(self):
        if self:
            return self[-1]
        return None

    def toc_title_cells(self):
        h1=CellSequence(1)
        h1.set_val(unicode_convert(self),0)
        return h1

    def toc_size_cells(self):
        h1=CellSequence(1)
        h1.set_val(unicode(len(self)),0)
        h1.set_style("right")
        return h1

    def toc_range_cells(self):
        h1=CellSequence(2)
        h1.set_val(unicode_convert(self.first()),0)
        h1.set_val(unicode_convert(self.last()),1)
        return h1
        
    # def table_header(self):
    #     return ""

    # def html_row(self,row):
    #     return "<tbody><tr><td>"+str(row)+"</td></tr></tbody>"

    # def table_rows(self):
    #     R=map(lambda r: self.html_row(r),self)
    #     return R

    def set_labelers_header(self,tab,start_col,num_rows):
        c=start_col
        for labeler in self.pagination.labelers:
            labeler.set_header(tab,c,num_rows)
            c+=labeler.num_cols

    def set_labelers_data(self,tab,row,start_row,start_col,num_rows):
        c=start_col
        for labeler in self.pagination.labelers:
            labeler.set_data(tab,row,start_row,c,num_rows)
            c+=labeler.num_cols

    def get_header_size(self,num_rows,num_cols):
        for labeler in self.pagination.labelers:
            num_cols+=labeler.num_cols
            num_rows=max(num_rows,labeler.num_header_rows)
        return num_rows,num_cols

    def get_data_params(self,row,num_cols,styles):
        for labeler in self.pagination.labelers:
            num_cols+=labeler.num_cols
            styles.append(labeler.get_style_row(row))
        style=" ".join(filter(bool,styles))
        return num_cols,style

class Pagination(object):
    """ Semplice paginatore che suddivide gli oggetti in liste di dimensione fissa e ne assegna una a ogni pagina.

    :param self.pagination_list_class: classe che gestisce le liste

    :param res_list: elenco di oggetti da paginare
    :param object_per_page: quanti oggetti in ogni pagina
    :param url_resolver: oggetto UrlResolver (il cui scope è "database")

    :param self.labelers: elenco di etichettatori da applicare

    """
    pagination_list_class = PaginationList


    def __init__(self,res_list,object_per_page,url_resolver):
        self.res_list=res_list
        self.object_per_page=object_per_page
        self.url_resolver=url_resolver
        self.labelers=[]

    def paginate(self):
        """ Suddivide gli oggetti.

        :return: Una lista di oggetti self.pagination_list_class.
        """

        res_paginated=[]
        n=0
        L=self.pagination_list_class(self)
        for r in self.res_list:
            L.append(r)
            if n<self.object_per_page:
                n+=1
                continue
            res_paginated.append(L)
            n=0
            L=self.pagination_list_class(self)
        if L:
            res_paginated.append(L)
        return res_paginated

    def header_table(self):
        """ Genera l'header  della tabella di indice. È  un header per
        una  tabela di quattro  colonne: la  prima contiene  il titolo
        della pagina,  la seconda quanti  elementi, la terza  il primo
        elemento e la quarta l'ultimo elemento della pagina.
            
        :return: Una stringa html con l'header.
        """
        tab=Table(1,4,tbody="thead")
        tab.set_all_th()
        c=0
        for lab in [ u"", u"quantità", u"first", u"last" ]:
            tab.set_val(0,c,lab)
            c+=1
        return tab

class PaginationListByIp(PaginationList):
    template_row_name="includes/pagination_list_byip_row.html"
    def __init__(self,pagination,vlan):
        PaginationList.__init__(self,pagination)
        self.vlan=vlan
        self.fixed=self.vlan.fixed
        self.public=self.vlan.public

    def __str__(self):
        return str(self.vlan)

    def __eq__(self,other):
        return self.vlan==other.vlan

    def __lt__(self,other):
        return self.vlan < other.vlan

    def __le__(self,other):
        if self.__eq__(other): return True
        return self.__lt__(other)
        
    def __gt__(self,other): return other.__lt__(self)

    def __ge__(self,other):
        if self.__eq__(other): return True
        return self.__gt__(other)

    def __ne__(self,other): return not self.__eq__(other)

    def first(self): return str(self.vlan.net)
    def last(self):  return str(self.vlan.last)

    def range(self):
        if self.vlan.netmask in [-1,0,32]: return ("","")
        return self.first(),self.last()

    def title_add(self): 
        T=u""
        if self.vlan.vid:
            T+=u"["+unicode(self.vlan.vid)+u"] "
        if not self.vlan.desc: return T
        if self.vlan.desc.has_key("desc") and self.vlan.desc["desc"]:
            T+=unicode_convert(self.vlan.desc["desc"])
        if self.vlan.desc.has_key("competenza") and self.vlan.desc["competenza"]:
            T+=u" ("+self.vlan.desc["competenza"]
            if self.vlan.desc.has_key("dubbio") and self.vlan.desc["dubbio"]:
                T+=self.vlan.desc["dubbio"]
            T+=")"
        return T

    # parte "title" dell'indice
    def toc_title_cells(self):
        h1=CellSequence(9)
        if isinstance(self.vlan,dns_tcpip.VirtualVLan):
            h1.set_all_colspan()
            h1.set_val(unicode_convert(self.vlan),0)
            return h1
        if self.vlan.localhost:
            h1.set_all_colspan()
            h1.set_val("localhost",0)
            return h1

        h1=CellSequence(9)
        h1.set_val(".",1,3,5)
        for i in [0,1,2,3]: 
            h1.set_val(self.vlan.net[i],2*i)
        h1.set_style("right border-none")
        h1.set_style("right border-left",0)
        h1.set_style("center border-none",1,3,5,7)
        h1.set_style("left border-right",8)
        if self.vlan.netmask not in [0,32]:
            h1.set_val("&nbsp;/&nbsp;",7)
            h1.set_val(self.vlan.netmask,8)
        h1.add_val("&nbsp;",8)
        return h1

    # parte "range" dell'indice
    def toc_range_cells(self):
        if isinstance(self.vlan,dns_tcpip.VirtualVLan):
            h1=CellSequence(22)
            h1.set_all_colspan()
            h1.set_val(u"&nbsp;",0)
            return h1
        if self.vlan.localhost:
            h1=CellSequence(22)
            h1.set_all_colspan()
            h1.set_val(u"&nbsp;",0)
            return h1

        h1=CellSequence(14)

        h1.set_val(u".",1,3,5,8,10,12)
        for i in [0,1,2,3]: 
            h1.set_val(self.vlan.net[i],2*i)
            h1.set_val(self.vlan.last[i],2*i+7)
        h1.set_style(u"right border-none")
        h1.set_style(u"right border-left",0,7)
        h1.set_style(u"center border-none",1,3,5,8,10,12)
        h1.set_style(u"left border-right",6,13)
        h1.add_val(u"&nbsp;",6,13)

        h2=CellSequence(8)
        h2.set_style(u"center")

        if self.vlan.vid:
            h2.set_val(self.vlan.vid,0)
        if not self.vlan.desc:
            return h1+h2

        params=[u"desc",u"location",u"address",u"competenza",u"dubbio",u"note",u"tabella"]

        if self.vlan.desc.has_key("competenza_color") and self.vlan.desc["competenza_color"]:
            h2.set_back_color(self.vlan.desc["competenza_color"])

        for k in range(0,len(params)):
            if self.vlan.desc.has_key(params[k]):
                h2.set_val(self.vlan.desc[params[k]],k+1)

        return h1+h2

    def known_vlan(self):
        return self.vlan.fixed

    ### header della tabella della pagina specifica
    # def table_header(self):
    #     tab=self.table_header_ctx()
    #     return str(tab)

    def table_header_ctx(self):
        num_rows,num_cols=self.get_header_size(2,5)
        tab=Table(num_rows,num_cols,tbody="thead")
        tab.set_all_th()
        tab.set_val(0,0,"IP")
        tab.set_val(0,1,"name")
        tab.set_val(0,2,"views")
        tab.set_span(0,0,rowspan=num_rows)
        tab.set_span(0,1,rowspan=num_rows)
        tab.set_span(0,2,colspan=3,rowspan=num_rows-1)
        tab.set_val(num_rows-1,2,"IN PTR")
        tab.set_val(num_rows-1,3,"IN A")
        tab.set_val(num_rows-1,4,"IN CNAME")
        self.set_labelers_header(tab,5,num_rows)

        return tab

    ### riga della tabella della pagina specifica (IP)
    def html_row_ctx(self,row):
        name_dict={}
        for view_set,res_name in row.res_name_list:
            key=res_name.name.lower()
            if not name_dict.has_key(key):
                name_dict[key]={ "ptr": [], "a": [], "cname": [] }
            name_dict[key]["a"].append(view_set)
            for cview_set,res_cname in res_name.res_cname_list:
                ckey=res_cname.name.lower()
                if view_set!=cview_set: continue
                if not name_dict.has_key(ckey):
                    name_dict[ckey]={ "ptr": [], "a": [], "cname": [] }
                name_dict[ckey]["cname"].append(view_set)

        for name,record_list in row.res.items():
            key=name.lower()
            if not name_dict.has_key(key):
                name_dict[key]={ "ptr": [], "a": [], "cname": [] }
            for view_set,record in record_list:
                name_dict[key]["ptr"].append(view_set)

        L=0
        for name,desc in name_dict.items():
            L+=max(len(desc["ptr"]),len(desc["a"]),len(desc["cname"]))

        num_cols,style=self.get_data_params(row,5,[])

        tab=Table(L,num_cols,style=style)
        tab.set_open(0,0,"res"+str(row.id),str(row.id),"row"+str(row.id),str(row.ip))
        tab.set_span(0,0,rowspan=L)
        tab.set_style(0,0,th=True,style="left")

        self.set_labelers_data(tab,row,0,5,L)

        name_list=name_dict.keys()
        name_list.sort()

        r=0
        for name in name_list:
            desc=name_dict[name]
            L=max(len(desc["ptr"]),len(desc["a"]),len(desc["cname"]))
            tab.set_val(r,1,self.res_link(name))
            tab.set_span(r,1,rowspan=L)
            tab.set_style(r,1,th=True,style="left")

            for ind,label in [ (2,"ptr"), (3,"a"), (4,"cname") ]:
                rb=r
                for view_set in desc[label]:
                    tab.set_val(rb,ind,view_set.cell())
                    rb+=1
            r+=L


        ### riga nascosta
        covered={
            "title": str(row.ip),
            "sub_tabs": [],
            "dom_id": "row"+str(row.id)
        }

        sub_title="IN PTR"
        sub_rows=[]

        sub_tab=Table(1,3,tbody="thead")
        sub_tab.set_all_th()
        sub_tab.set_val(0,0,"name")
        sub_tab.set_val(0,1,"views")
        sub_tab.set_val(0,2,"record")
        sub_tab.set_row_style(0,"no-hover")

        sub_rows.append(sub_tab)

        for name,record_list in row.res.items():
            sub_tab=Table(len(record_list),3)
            sub_tab.set_span(0,0,rowspan=len(record_list))
            sub_tab.set_val(0,0,self.res_link(name))
            r=0
            for view_set,record in record_list:
                sub_tab.set_val(r,1,view_set.cell())
                sub_tab.set_val(r,2,self.record_link(record))
                r+=1
            sub_rows.append(sub_tab)

        covered["sub_tabs"].append( (sub_title,sub_rows) )

        sub_title="IN A / IN CNAME"
        sub_rows=[]

        sub_tab=Table(2,5,tbody="thead")
        sub_tab.set_all_th()
        sub_tab.set_row_style(0,"no-hover")
        sub_tab.set_row_style(1,"no-hover")
        sub_tab.set_val(0,0,"IN A")
        sub_tab.set_span(0,0,colspan=3)
        sub_tab.set_val(0,4,"IN CNAME")
        sub_tab.set_span(0,4,colspan=2)
        sub_tab.set_val(1,0,"name")
        sub_tab.set_val(1,1,"views")
        sub_tab.set_val(1,2,"record")
        sub_tab.set_val(1,3,"name")
        sub_tab.set_val(1,4,"record")

        sub_rows.append(sub_tab)
        
        for view_set,res_name in row.res_name_list:
            key=res_name.name.lower()
            cname_list=map(lambda x: x[1],filter(lambda x: x[0]==view_set,res_name.res_cname_list))
            record_list=map(lambda x: x[1],filter(lambda x: x[0]==view_set,res_name.res[row.ip]))
            
            rowspan=max(1,len(cname_list),len(record_list))
            n_tab=Table(rowspan,5)
            n_tab.set_val(0,0,self.res_link(res_name.name))
            n_tab.set_span(0,0,rowspan=rowspan)
            n_tab.set_val(0,1,view_set.cell())
            n_tab.set_span(0,1,rowspan=rowspan)

            r=0
            for record in record_list:
                n_tab.set_val(r,2,self.record_link(record))
                r+=1

            r=0
            for res_cname in cname_list:
                n_tab.set_val(r,3,self.res_link(res_cname.name))
                c_record_list=map(lambda x: x[1],filter(lambda x: x[0]==view_set,res_cname.res[res_name.name]))
                s="<br/>".join(map(self.record_link,c_record_list))
                n_tab.set_val(r,4,s)
                r+=1
            sub_rows.append(n_tab)

        covered["sub_tabs"].append( (sub_title,sub_rows) )
        #tab.set_val(last,1,S)

        return {"main": tab,"hidden": covered }


    ### riga della tabella della pagina specifica (IP)
    def html_row(self,row):
        name_dict={}
        for view_set,res_name in row.res_name_list:
            key=res_name.name.lower()
            if not name_dict.has_key(key):
                name_dict[key]={ "ptr": [], "a": [], "cname": [] }
            name_dict[key]["a"].append(view_set)
            for cview_set,res_cname in res_name.res_cname_list:
                ckey=res_cname.name.lower()
                if view_set!=cview_set: continue
                if not name_dict.has_key(ckey):
                    name_dict[ckey]={ "ptr": [], "a": [], "cname": [] }
                name_dict[ckey]["cname"].append(view_set)

        for name,record_list in row.res.items():
            key=name.lower()
            if not name_dict.has_key(key):
                name_dict[key]={ "ptr": [], "a": [], "cname": [] }
            for view_set,record in record_list:
                name_dict[key]["ptr"].append(view_set)

        L=0
        for name,desc in name_dict.items():
            L+=max(len(desc["ptr"]),len(desc["a"]),len(desc["cname"]))
        last=L

        open_label='<a name="res'+str(row.id)+'"></a>'
        for lab,other,icon in [ ("open","close","right"),("close","open","down") ]:
            open_label+='<a href="" class="'+lab+'" '
            open_label+=' id="'+lab+str(row.id)+'"'
            open_label+=' data-'+other+'="#'+other+str(row.id)+'"'
            open_label+=' data-target="#row'+str(row.id)+'">'
            open_label+='&nbsp;<i class="fa fa-caret-'+icon+'"></i>&nbsp;</a>'

        num_cols,style=self.get_data_params(row,5,[])

        tab=Table(L+1,num_cols,style=style)
        tab.set_val(0,0,open_label+str(row.ip))
        tab.set_span(0,0,rowspan=L)
        tab.set_style(0,0,th=True,style="left")

        self.set_labelers_data(tab,row,0,5,L)

        name_list=name_dict.keys()
        name_list.sort()

        r=0
        for name in name_list:
            desc=name_dict[name]
            L=max(len(desc["ptr"]),len(desc["a"]),len(desc["cname"]))
            tab.set_val(r,1,self.res_link(name))
            tab.set_span(r,1,rowspan=L)
            tab.set_style(r,1,th=True,style="left")

            for ind,label in [ (2,"ptr"), (3,"a"), (4,"cname") ]:
                rb=r
                for view_set in desc[label]:
                    tab.set_val(rb,ind,view_set.cell())
                    rb+=1
            r+=L

        tab.set_span(last,1,colspan=num_cols-1)
        tab.set_style(last,0,th=True,style="left")
        tab.set_style(last,1,style="tab_cell_detail")
        tab.set_row_style(last,"start_hidden no_hover")
        tab.set_row_id(last,"row"+str(row.id))

        S="<h1>"+str(row.ip)+"</h1>"
        S+="<h2>IN PTR</h2>"

        S+="<table>"
        S+="<thead><tr class='no-hover'>"
        S+="<th>name</th><th>views</th><th>record</th>"
        S+="</tr></thead>"
        for name,record_list in row.res.items():
            S+='<tbody><tr><td rowspan="'+str(len(record_list))+'">'+self.res_link(name)+"</td>"
            primo=True
            for view_set,record in record_list:
                if primo: primo=False
                else: S+="<tr>"
                S+="<td>"+view_set.cell()+"</td>"
                S+="<td>"+self.record_link(record)+"</td>"
                S+='</tr>'
            S+="</tbody>"
        S+="</table>"

        S+="<h2>IN A / IN CNAME</h2>"

        S+="<table>"

        S+="<thead><tr class='no-hover'>"
        S+="<th colspan='3'>IN A</th><th colspan='2'>IN CNAME</th></tr>"
        S+="<tr><th>name</th><th>views</th><th>record</th>"
        S+="<th>name</th><th>record</th>"
        S+="</tr></thead>"
        
        for view_set,res_name in row.res_name_list:
            key=res_name.name.lower()
            cname_list=map(lambda x: x[1],filter(lambda x: x[0]==view_set,res_name.res_cname_list))
            record_list=map(lambda x: x[1],filter(lambda x: x[0]==view_set,res_name.res[row.ip]))
            
            rowspan=max(1,len(cname_list),len(record_list))
            n_tab=Table(rowspan,5)
            n_tab.set_val(0,0,self.res_link(res_name.name))
            n_tab.set_span(0,0,rowspan=rowspan)
            n_tab.set_val(0,1,view_set.cell())
            n_tab.set_span(0,1,rowspan=rowspan)

            r=0
            for record in record_list:
                n_tab.set_val(r,2,self.record_link(record))
                r+=1

            r=0
            for res_cname in cname_list:
                n_tab.set_val(r,3,self.res_link(res_cname.name))
                c_record_list=map(lambda x: x[1],filter(lambda x: x[0]==view_set,res_cname.res[res_name.name]))
                s="<br/>".join(map(self.record_link,c_record_list))
                n_tab.set_val(r,4,s)
                r+=1
            S+=str(n_tab)
        S+="</table>\n"

        tab.set_val(last,1,S)

        return str(tab)


class PaginationByIp(Pagination):
    def __init__(self,res_list,object_per_page,url_resolver,vlan_manager):
        Pagination.__init__(self,res_list,object_per_page,url_resolver)
        self.vlan_manager=vlan_manager
            
    def paginate(self):
        net_list={}

        for vlan in self.vlan_manager.all_vlans():
            print "%15.15s %15.15s %d" % (str(vlan.net),str(vlan.last),vlan.netmask)
            net_list[vlan]=PaginationListByIp(self,vlan)

        no_net=PaginationListByIp(self,dns_tcpip.VirtualVLan("no net",0))

        for r in self.res_list:
            t=r.ip.split(".")
            if len(t)!=4: 
                no_net.append(r)
                continue
            vlan=self.vlan_manager(r.ip)
            if not net_list.has_key(vlan):
                net_list[vlan]=PaginationListByIp(self,vlan)
            net_list[vlan].append(r)

        all_pages=net_list.values()
        public_pages=filter(lambda x: x.public,all_pages)
        res_paginated=filter(lambda x: not x.public,all_pages)

        sparse_public=PaginationListByIp(self,dns_tcpip.VirtualVLan("sparse public addresses",1,public=True))
        for page in public_pages:
            if page.fixed: 
                res_paginated.append(page)
                continue
            if len(page)>=32:
                res_paginated.append(page)
                continue
            for r in page:
                sparse_public.append(r)

        if sparse_public:
            res_paginated.append(sparse_public)
        if no_net:
            res_paginated.append(no_net)

        res_paginated.sort()
            
        return res_paginated


    def _aggregate_net(self,res_paginated):

        type_a=[]
        type_b=[]
        type_ca=[]
        type_cb=[]
        type_da=[]
        type_db=[]
        type_b_v=[]
        type_ca_v=[]
        type_cb_v=[]

        for pag_list in res_paginated:
            if pag_list.net=="no net":
                type_a.append(pag_list)
                continue
            t=pag_list.net.split(".")
            if t[0]=="127":
                type_a.append(pag_list)
                continue
            if t[0]=="10":
                if pag_list.vlan_id:
                    type_b_v.append(pag_list)
                    continue
                type_b.append(pag_list)
                continue
            if t[0] in ["172","192"]:
                if t[0]=="192" and t[1]=="168":
                    if pag_list.vlan_id:
                        type_ca_v.append(pag_list)
                        continue
                    type_ca.append(pag_list)
                    continue
                if t[0]=="172" and (int(t[1]) in range(16,32)):
                    if pag_list.vlan_id:
                        type_cb_v.append(pag_list)
                        continue
                    type_cb.append(pag_list)
                    continue
            if pag_list.vlan_id or len(pag_list)>=64:
                type_da.append(pag_list)
                continue
            type_db.append(pag_list)
        type_b=self._resplit(type_b,"10.0.0.0",8)
        type_cb=self._resplit(type_cb,"172.16.0.0",12)
        type_ca=self._resplit(type_ca,"192.168.0.0",16)
        type_db=self._resplit(type_db,"0.0.0.0",0)
        type_b+=type_b_v
        type_ca+=type_ca_v
        type_cb+=type_cb_v
        type_a.sort()   # no net
        type_b.sort()   # 10.
        type_ca.sort()  # 172.x.
        type_cb.sort()  # 192.168.
        type_da.sort()  # pubbliche > 64 o in vlan
        type_db.sort()  # altre pubbliche
        ret=type_b+type_cb+type_ca+type_da+type_db+type_a
        map(lambda x: x.sort(),ret)

        return ret

    def _resplit(self,res_paginated,net,netmask):
        if len(res_paginated)<=1: return res_paginated
        if netmask>=24:
            return res_paginated
        L=0
        for pag_list in res_paginated:
            L+=len(pag_list)
        if L<=256:
            new_pag_list=PaginationListByIp(self,net,netmask)
            for pag_list in res_paginated:
                new_pag_list.extend(pag_list)
            return [new_pag_list]
        t=net.split(".")
        netmask+=1
        if netmask>24:
            new_net_base=t[0]+"."+t[1]+"."+t[2]+"."
            new_net_suffix=""
            ind=3
            L=int(math.pow(2,32-netmask))
        elif netmask>16:
            new_net_base=t[0]+"."+t[1]+"."
            new_net_suffix=".0"
            ind=2
            L=int(math.pow(2,24-netmask))
        elif netmask>8:
            new_net_base=t[0]+"."
            new_net_suffix=".0.0"
            ind=1
            L=int(math.pow(2,16-netmask))
        else:
            new_net_base=""
            new_net_suffix=".0.0.0"
            ind=0
            L=int(math.pow(2,8-netmask))
        base=int(t[ind])
        half=base+L
        net_a=new_net_base+str(base)+new_net_suffix
        net_b=new_net_base+str(half)+new_net_suffix

        lato_a=[]
        lato_b=[]
        for pag_list in res_paginated:
            q=pag_list.net.split(".")
            if int(q[ind])<half:
                lato_a.append(pag_list)
            else:
                lato_b.append(pag_list)
        return self._resplit(lato_a,net_a,netmask)+self._resplit(lato_b,net_b,netmask)

    def header_table(self):
        tab=Table(1,32,tbody="thead")
        tab.set_all_th()
        c=0
        for cspan,lab in [ (9,u""), 
                           (1,u"quantità"), (7,u"first"), (7,u"last"),
                           (2,u"vlan"),(2,u"indirizzo"),(2,u"competenza"),(1,u"note"),(1,u"tabella") ]:
            tab.set_val(0,c,lab)
            tab.set_span(0,c,colspan=cspan)
            c+=cspan
        return tab

class PaginationListByName(PaginationList):
    template_row_name="includes/pagination_list_byname_row.html"

    def __init__(self,pagination,net,group_len=-1,group_seq=-1):
        PaginationList.__init__(self,pagination)
        self.net=net
        self.group_len=group_len
        self.group_seq=group_seq


    def __str__(self): 
        if self.group_len<=0:
            return self.net
        return self.net+" ("+str(self.group_seq)+"/"+str(self.group_len)+")"

    def __eq__(self,other): 
        flag=( self.net==other.net )
        if self.group_len<=0:
            return flag and (self.group_len<=0)
        flag=flag and (self.group_len==other.group_len)
        flag=flag and (self.group_seq==other.group_seq)
        return flag

    def __lt__(self,other):
        for lab in [ "localhost","nomi isolati" ]:
            if self.net==lab:
                return other.net!=lab
            if other.net==lab: return False

        s_t=self.net.strip(".").split(".")
        o_t=other.net.strip(".").split(".")
        s_t.reverse()
        o_t.reverse()

        L_s=len(s_t)
        L_o=len(o_t)
        L=min(L_s,L_o)
        
        for n in range(0,L):
            if s_t[n]<o_t[n]: return True
            if s_t[n]>o_t[n]: return False

        if self.group_len<=0:
            return L_s<L_o

        if L_s!=L_o: return L_s<L_o

        return self.group_seq<other.group_seq

    def __ne__(self,other): return not self.__eq__(other)

    def __le__(self,other):
        if self.__eq__(other): return True
        return self.__lt__(other)
        
    def __gt__(self,other): return other.__lt__(self)

    def __ge__(self,other):
        if self.__eq__(other): return True
        return self.__gt__(other)

    ### header della tabella della pagina specifica
    def table_header_ctx(self):
        num_rows,num_cols=self.get_header_size(2,6)
        tab=Table(num_rows,num_cols,tbody="thead")
        tab.set_all_th()
        tab.set_val(0,0,"name")
        tab.set_val(0,1,"IP")
        tab.set_val(0,3,"views")
        tab.set_span(0,0,rowspan=num_rows)
        tab.set_span(0,1,colspan=2,rowspan=num_rows-1)
        tab.set_val(num_rows-1,1,"")
        tab.set_val(num_rows-1,2,"ping")
        tab.set_span(0,3,colspan=3,rowspan=num_rows-1)
        tab.set_val(num_rows-1,3,"IN A")
        tab.set_val(num_rows-1,4,"IN CNAME")
        tab.set_val(num_rows-1,5,"IN PTR")

        self.set_labelers_header(tab,6,num_rows)
        return tab

    # def table_header(self):
    #     tab=self.table_header_ctx()
    #     return str(tab)

    # ### riga della tabella della pagina specifica (name)
    # def html_row(self,row):

    #     ip_dict={}
    #     if row.record_type in ["A"]:
    #         for ip,vlist in row.res.items():
    #             if not ip_dict.has_key(ip):
    #                 ip_dict[ip]={ "ptr": [], "a": [], "cname": [] }
    #             for view_set,record in vlist:
    #                 ip_dict[ip]["a"].append(view_set)
    #         for view_set,res_ip in row.res_ip_list:
    #             key=res_ip.ip
    #             if not res_ip.res.has_key(row.name): continue
    #             if not ip_dict.has_key(key):
    #                 ip_dict[key]={ "ptr": [], "a": [], "cname": [] }
    #             ip_dict[key]["ptr"].append(view_set)
    #     elif row.record_type in ["PTR"]:
    #         for view_set,res_ip in row.res_ip_list:
    #             key=res_ip.ip
    #             if not ip_dict.has_key(key):
    #                 ip_dict[key]={ "ptr": [], "a": [], "cname": [] }
    #             ip_dict[key]["ptr"].append(view_set)
    #     else:
    #         for cname_view_set,res_aname in row.res_name_list:
    #             for ip,vlist in res_aname.res.items():
    #                 for view_set,record in vlist:
    #                     if cname_view_set!=view_set: continue
    #                     if not ip_dict.has_key(ip):
    #                         ip_dict[ip]={ "ptr": [], "a": [], "cname": [] }
    #                     ip_dict[ip]["cname"].append(view_set)
    #             for view_set,res_ip in row.res_ip_list:
    #                 key=res_ip.ip
    #                 if not res_ip.res.has_key(row.name): continue
    #                 if not ip_dict.has_key(key):
    #                     ip_dict[key]={ "ptr": [], "a": [], "cname": [] }
    #                 ip_dict[key]["ptr"].append(view_set)

    #     L=0
    #     for ip,desc in ip_dict.items():
    #         L+=max(len(desc["ptr"]),len(desc["a"]),len(desc["cname"]))
    #     last=L

    #     open_label='<a name="res'+str(row.id)+'"></a>'
    #     for lab,other,icon in [ ("open","close","right"),("close","open","down") ]:
    #         open_label+='<a href="" class="'+lab+'" '
    #         open_label+=' id="'+lab+str(row.id)+'"'
    #         open_label+=' data-'+other+'="#'+other+str(row.id)+'"'
    #         open_label+=' data-target="#row'+str(row.id)+'">'
    #         open_label+='&nbsp;<i class="fa fa-caret-'+icon+'"></i>&nbsp;</a>'

    #     num_cols,style=self.get_data_params(row,6,[])

    #     tab=Table(L+1,num_cols,style=style)
    #     tab.set_val(0,0,open_label+str(row.name))
    #     tab.set_span(0,0,rowspan=L)
    #     tab.set_style(0,0,th=True,style="left")

    #     self.set_labelers_data(tab,row,0,6,L)

    #     ip_list=ip_dict.keys()
    #     ip_list.sort(cmp=ip_cmp)

    #     r=0
    #     for ip in ip_list:
    #         desc=ip_dict[ip]
    #         L=max(len(desc["ptr"]),len(desc["a"]),len(desc["cname"]))
    #         tab.set_val(r,1,self.res_link(ip))
    #         #tab.set_val(r,2,self.pagination.ping_map(ip))
    #         tab.set_val(r,2,"")
    #         tab.set_span(r,1,rowspan=L)
    #         tab.set_style(r,1,th=True,style="left")
    #         tab.set_span(r,2,rowspan=L)
    #         tab.set_style(r,2,th=True,style="left")

    #         for ind,label in [ (3,"a"), (4,"cname"), (5,"ptr") ]:
    #             rb=r
    #             for view_set in desc[label]:
    #                 tab.set_val(rb,ind,view_set.cell())
    #                 rb+=1
    #         r+=L

    #     tab.set_span(last,1,colspan=num_cols-1)
    #     tab.set_style(last,0,th=True,style="left")
    #     tab.set_style(last,1,style="tab_cell_detail")
    #     tab.set_row_style(last,"start_hidden no_hover")
    #     tab.set_row_id(last,"row"+str(row.id))

    #     S="<h1>"+str(row.name)+"</h1>"

    #     if row.res_ip_list:
    #         S+="<h2>IN PTR</h2>"
    #         S+="<table>"
    #         S+="<thead><tr class='no-hover'>"
    #         S+="<th>IP</th><th>views</th><th>record</th>"
    #         S+="</tr></thead>"

    #         for view_set,res_ip in row.res_ip_list:
    #             for name,record_list in res_ip.res.items():
    #                 if name!=row.name: continue
    #                 S+='<tbody><tr><td rowspan="'+str(len(record_list))+'">'+self.res_link(res_ip.ip)+"</td>"
    #                 primo=True
    #                 for view_set,record in record_list:
    #                     if primo: primo=False
    #                     else: S+="<tr>"
    #                     S+="<td>"+view_set.cell()+"</td>"
    #                     S+="<td>"+self.record_link(record)+"</td>"
    #                     S+='</tr>'
    #                 S+="</tbody>"
    #         S+="</table>"

    #     if row.record_type in ["PTR"]:
    #         tab.set_val(last,1,S)
    #         return str(tab)

    #     if row.record_type in ["A"]:
    #         S+="<h2>IN A</h2>"
    #         S+="<table>"
    #         S+="<thead><tr class='no-hover'>"
    #         S+="<tr><th>IP</th><th>views</th><th>record</th>"
    #         S+="</tr></thead>"

    #         for ip,record_list in row.res.items():
    #             S+='<tbody><tr><td rowspan="'+str(len(record_list))+'">'+self.res_link(ip)+"</td>"
    #             primo=True
    #             for view_set,record in record_list:
    #                 if primo: primo=False
    #                 else: S+="<tr>"
    #                 S+="<td>"+view_set.cell()+"</td>"
    #                 S+="<td>"+self.record_link(record)+"</td>"
    #                 S+='</tr>'
    #             S+="</tbody>"
    #         S+="</table>\n"
    #         tab.set_val(last,1,S)

    #         return str(tab)

    #     S+="<h2>IN CNAME</h2>"
    #     S+="<table>"
    #     S+="<thead><tr class='no-hover'>"
    #     S+="<tr><th>alias</th><th>views</th><th>record</th>"
    #     S+="</tr></thead>"

    #     for name,record_list in row.res.items():
    #         S+='<tbody><tr><td rowspan="'+str(len(record_list))+'">'+self.res_link(name)+"</td>"
    #         primo=True
    #         for view_set,record in record_list:
    #             if primo: primo=False
    #             else: S+="<tr>"
    #             S+="<td>"+view_set.cell()+"</td>"
    #             S+="<td>"+self.record_link(record)+"</td>"
    #             S+='</tr>'
    #         S+="</tbody>"

    #     S+="</table>\n"

    #     S+="<h2>IN A</h2>"
    #     S+="<table>"
    #     S+="<thead><tr class='no-hover'>"
    #     S+="<tr><th>IP</th><th>views</th><th>record</th>"
    #     S+="</tr></thead>"



    #     primo=True
    #     for c_view_set,res_aname in row.res_name_list:
    #         S+='<tbody>'
    #         for ip,vlist in res_aname.res.items():
    #             S+='<tr><td rowspan="'+str(len(vlist))+'">'+self.res_link(ip)+"</td>"
    #             primo=True
    #             for view_set,record in record_list:
    #                 if view_set!=c_view_set: continue
    #                 if primo: primo=False
    #                 else: S+="<tr>"
    #                 S+="<td>"+view_set.cell()+"</td>"
    #                 S+="<td>"+self.record_link(record)+"</td>"
    #                 S+='</tr>'
    #         S+='</tbody>'

    #     S+="</table>\n"
    #     tab.set_val(last,1,S)

    #     return str(tab)

    #     # ### QUI

    #     # L=0
    #     # for key,desc in row.res.items():
    #     #     L+=len(desc)
    #     # if not L: return ""

    #     # t_rowspan=L
    #     # rowspan=L
    #     # if row.record_type=="A":
    #     #     for view_set,row_ip in row.res_ip_list:
    #     #         xL=0
    #     #         for key,desc in row_ip.res.items():
    #     #             if key!=row.name: continue
    #     #             xL+=len(desc)
    #     #         rowspan+=xL
    #     # elif row.record_type=="CNAME":
    #     #     rowspan=0
    #     #     for view_set,row_name in row.res_name_list:
    #     #         xL=0
    #     #         for key,desc in row_name.res.items():
    #     #             xL+=len(desc)
    #     #         rowspan+=xL
    #     #     rowspan=max(L,rowspan)
    #     #     t_rowspan=rowspan
    #     # a_name='<a name="res'+str(row.id)+'"></a>'

    #     # num_cols,style=self.get_data_params(row,8,[])

    #     # tab=Table(rowspan,num_cols,style=style)

    #     # self.set_labelers_data(tab,row,0,8,rowspan)

    #     # tab.set_style(0,0,th=True)
    #     # tab.set_span(0,0,rowspan=rowspan)
    #     # tab.set_val(0,0,a_name+row.name)

    #     # tab.set_span(0,1,rowspan=t_rowspan)
    #     # tab.set_val(0,1,"IN "+row.record_type)

    #     # if row.record_type in [ "PTR","A" ]:
    #     #     r=0
    #     #     for key,desc in row.res.items():
    #     #         L=len(desc)
    #     #         tab.set_val(r,2,self.res_link(key))
    #     #         tab.set_span(r,2,rowspan=L)
    #     #         for view_set,record in desc:
    #     #             tab.set_val(r,3,view_set.cell())
    #     #             tab.set_val(r,4,self.record_link(record))
    #     #             r+=1

    #     #     if row.record_type=="PTR": return str(tab)

    #     #     if rowspan==t_rowspan: return str(tab)
    #     #     tab.set_val(r,1,"IN PTR")
    #     #     tab.set_span(r,1,rowspan-t_rowspan)
    #     #     for view_set,row_ip in row.res_ip_list:
    #     #         xL=0
    #     #         xr=r
    #     #         for key,desc in row_ip.res.items():
    #     #             if key!=row.name: continue
    #     #             L=len(desc)
    #     #             xL+=L
    #     #             tab.set_val(r,6,key)
    #     #             tab.set_span(r,6,rowspan=L)
    #     #             for iview_set,record in desc:
    #     #                 tab.set_val(r,4,self.record_link(record))
    #     #                 tab.set_val(r,5,iview_set.cell())
    #     #                 r+=1
    #     #         if xL:
    #     #             tab.set_val(xr,2,self.res_link(row_ip.ip))
    #     #             tab.set_span(xr,2,rowspan=xL)
    #     #             tab.set_val(xr,3,view_set.cell())
    #     #             tab.set_span(xr,3,rowspan=xL)
    #     #     return str(tab)

    #     # ## cname
    #     # r=0
    #     # for key,desc in row.res.items():
    #     #     L=len(desc)
    #     #     tab.set_val(r,5,self.res_link(key))
    #     #     tab.set_span(r,5,rowspan=L)
    #     #     for view_set,record in desc:
    #     #         tab.set_val(r,3,view_set.cell())
    #     #         tab.set_val(r,4,self.record_link(record))
    #     #         r+=1

    #     # r=0
    #     # for view_set,row_name in row.res_name_list:
    #     #     for key,desc in row_name.res.items():
    #     #         L=len(desc)
    #     #         tab.set_val(r,2,self.res_link(key))
    #     #         tab.set_span(r,2,rowspan=L)
    #     #         for view_set,record in desc:
    #     #             tab.set_val(r,6,view_set.cell())
    #     #             tab.set_val(r,7,self.record_link(record))
    #     #             r+=1

    #     # # elif row.record_type=="CNAME":
    #     # #     r=0
    #     # #     for view_set,res_name in row.res_name_list:
    #     # #         tab.set_val(r,6,view_set.cell())
    #     # #         tab.set_val(r,7,str(res_name))
    #     # #         tab.set_span(r,7,colspan=3)
    #     # #         r+=1
    #     # # else:
    #     # #     r=0
    #     # #     for view_set,res_ip in row.res_ip_list:
    #     # #         tab.set_val(r,6,view_set.cell())
    #     # #         tab.set_val(r,7,str(res_ip))
    #     # #         tab.set_span(r,7,colspan=3)
    #     # #         r+=1
    #     # return str(tab)


    ### riga della tabella della pagina specifica (name)
    def html_row_ctx(self,row):

        ip_dict={}
        if row.record_type in ["A"]:
            for ip,vlist in row.res.items():
                if not ip_dict.has_key(ip):
                    ip_dict[ip]={ "ptr": [], "a": [], "cname": [] }
                for view_set,record in vlist:
                    ip_dict[ip]["a"].append(view_set)
            for view_set,res_ip in row.res_ip_list:
                key=res_ip.ip
                if not res_ip.res.has_key(row.name): continue
                if not ip_dict.has_key(key):
                    ip_dict[key]={ "ptr": [], "a": [], "cname": [] }
                ip_dict[key]["ptr"].append(view_set)
        elif row.record_type in ["PTR"]:
            for view_set,res_ip in row.res_ip_list:
                key=res_ip.ip
                if not ip_dict.has_key(key):
                    ip_dict[key]={ "ptr": [], "a": [], "cname": [] }
                ip_dict[key]["ptr"].append(view_set)
        else:
            for cname_view_set,res_aname in row.res_name_list:
                for ip,vlist in res_aname.res.items():
                    for view_set,record in vlist:
                        if cname_view_set!=view_set: continue
                        if not ip_dict.has_key(ip):
                            ip_dict[ip]={ "ptr": [], "a": [], "cname": [] }
                        ip_dict[ip]["cname"].append(view_set)
                for view_set,res_ip in row.res_ip_list:
                    key=res_ip.ip
                    if not res_ip.res.has_key(row.name): continue
                    if not ip_dict.has_key(key):
                        ip_dict[key]={ "ptr": [], "a": [], "cname": [] }
                    ip_dict[key]["ptr"].append(view_set)

        num_cols,style=self.get_data_params(row,6,[])

        if not ip_dict:
            tab=Table(1,num_cols,style="yellow")
            tab.set_val(0,0,str(row.name))
            tab.set_style(0,0,th=True,style="left")
            tab.set_span(0,1,colspan=num_cols-1)
            tab.set_val(0,1,"no record")
            return { "main": tab, "hidden": {} }

        L=0
        for ip,desc in ip_dict.items():
            L+=max(len(desc["ptr"]),len(desc["a"]),len(desc["cname"]))

        tab=Table(L,num_cols,style=style)

        tab.set_open(0,0,"res"+str(row.id),str(row.id),"row"+str(row.id),str(row.name))
        tab.set_span(0,0,rowspan=L)
        tab.set_style(0,0,th=True,style="left")

        self.set_labelers_data(tab,row,0,6,L)

        ip_list=ip_dict.keys()
        ip_list.sort(cmp=ip_cmp)

        r=0
        for ip in ip_list:
            desc=ip_dict[ip]
            L=max(len(desc["ptr"]),len(desc["a"]),len(desc["cname"]))
            tab.set_val(r,1,self.res_link(ip))
            tab.set_val(r,2,"")
            tab.set_span(r,1,rowspan=L)
            tab.set_style(r,1,th=True,style="left")
            tab.set_span(r,2,rowspan=L)
            tab.set_style(r,2,th=True,style="left")

            for ind,label in [ (3,"a"), (4,"cname"), (5,"ptr") ]:
                rb=r
                for view_set in desc[label]:
                    tab.set_val(rb,ind,view_set.cell())
                    rb+=1
            r+=L

        ### riga nascosta
        covered={
            "title": str(row.name),
            "sub_tabs": [],
            "dom_id": "row"+str(row.id)
        }

        if row.res_ip_list:
            sub_title="IN PTR"
            sub_rows=[]

            sub_tab=Table(1,3,tbody="thead")
            sub_tab.set_all_th()
            sub_tab.set_val(0,0,"ip")
            sub_tab.set_val(0,1,"views")
            sub_tab.set_val(0,2,"record")
            sub_tab.set_row_style(0,"no-hover")

            sub_rows.append(sub_tab)


            for view_set,res_ip in row.res_ip_list:
                for name,record_list in res_ip.res.items():
                    if name!=row.name: continue
                    sub_tab=Table(len(record_list),3)
                    sub_tab.set_span(0,0,rowspan=len(record_list))
                    sub_tab.set_val(0,0,self.res_link(res_ip.ip))
                    r=0
                    for view_set,record in record_list:
                        sub_tab.set_val(r,1,view_set.cell())
                        sub_tab.set_val(r,2,self.record_link(record))
                        r+=1
                    sub_rows.append(sub_tab)

            covered["sub_tabs"].append( (sub_title,sub_rows) )
        
        if row.record_type in ["PTR"]:
            return {"main": tab, "hidden": covered }

        if row.record_type in ["A"]:
            sub_title="IN A"
            sub_rows=[]

            sub_tab=Table(1,3,tbody="thead")
            sub_tab.set_all_th()
            sub_tab.set_val(0,0,"IP")
            sub_tab.set_val(0,1,"views")
            sub_tab.set_val(0,2,"record")
            sub_tab.set_row_style(0,"no-hover")

            sub_rows.append(sub_tab)

            for ip,record_list in row.res.items():
                sub_tab=Table(len(record_list),3)
                sub_tab.set_span(0,0,rowspan=len(record_list))
                sub_tab.set_val(0,0,self.res_link(ip))
                r=0
                for view_set,record in record_list:
                    sub_tab.set_val(r,1,view_set.cell())
                    sub_tab.set_val(r,2,self.record_link(record))
                    r+=1
                sub_rows.append(sub_tab)
            covered["sub_tabs"].append( (sub_title,sub_rows) )

            return { "main": tab, "hidden": covered }

        sub_title="IN CNAME"
        sub_rows=[]

        sub_tab=Table(1,3,tbody="thead")
        sub_tab.set_all_th()
        sub_tab.set_val(0,0,"alias")
        sub_tab.set_val(0,1,"views")
        sub_tab.set_val(0,2,"record")
        sub_tab.set_row_style(0,"no-hover")

        sub_rows.append(sub_tab)

        for name,record_list in row.res.items():
            sub_tab=Table(len(record_list),3)
            sub_tab.set_span(0,0,rowspan=len(record_list))
            sub_tab.set_val(0,0,self.res_link(name))
            r=0
            for view_set,record in record_list:
                sub_tab.set_val(r,1,view_set.cell())
                sub_tab.set_val(r,2,self.record_link(record))
                r+=1

        covered["sub_tabs"].append( (sub_title,sub_rows) )

        sub_title="IN A"
        sub_rows=[]

        sub_tab=Table(1,3,tbody="thead")
        sub_tab.set_all_th()
        sub_tab.set_val(0,0,"IP")
        sub_tab.set_val(0,1,"views")
        sub_tab.set_val(0,2,"record")
        sub_tab.set_row_style(0,"no-hover")
        
        sub_rows.append(sub_tab)

        for c_view_set,res_aname in row.res_name_list:
            for ip,vlist in res_aname.res.items():
                sub_tab=Table(len(vlist),3)
                sub_tab.set_span(0,0,rowspan=len(vlist))
                sub_tab.set_val(0,0,self.res_link(ip))
                r=0
                for view_set,record in record_list:
                    if view_set!=c_view_set: continue
                    sub_tab.set_val(r,1,view_set.cell())
                    sub_tab.set_val(r,2,self.record_link(record))
                    r+=1
                sub_rows.append(sub_tab)

        covered["sub_tabs"].append( (sub_title,sub_rows) )

        return {"main": tab,"hidden": covered }

    def toc_range_cells(self):
        h1=CellSequence(2)
        if self.first():
            h1.set_val(str(self.first().name),0)
        if self.last():
            h1.set_val(str(self.last().name),1)
        return h1

    def toc_title_cells(self):
        h1=CellSequence(1)
        L=len(self.net.strip(".").split("."))
        if L<=1:
            h1.set_val(unicode_convert(self),0)
            return h1
        prefix=u''.join(map(lambda x: u"&nbsp;&nbsp;",range(0,L-1)))
        h1.set_val(prefix+unicode_convert(self),0)
        return h1

class PaginationByName(Pagination):
    pagination_list_class = PaginationListByName

    def __init__(self,res_list,object_per_page,url_resolver):
        Pagination.__init__(self,res_list,object_per_page,url_resolver)

    def paginate(self):
        res_paginated=[]
        n=0
        L=None
        current_net=""
        net_list={}
        for r in self.res_list:
            t=r.name.strip(".").split(".")
            if len(t)==1:
                net="nomi isolati"
            else:
                net="."+t[-1]
            if net==".localdomain":
                net="localhost"
            if not net_list.has_key(net):
                net_list[net]=PaginationListByName(self,net)
            net_list[net].append(r)
        res_paginated=self._split_net(net_list.values())
        res_paginated.sort()
        return res_paginated

    def _split_net(self,res_paginated): 
        new_res_paginated=[]
        for res_list in res_paginated:
            if res_list.net=="nomi isolati":
                new_res_paginated+=self._split_by_alphabet(res_list,"nomi isolati")
                continue
            if res_list.net=="localhost":
                new_res_paginated.append(res_list)
                continue
            new_res_paginated+=self._split_by_subnet(res_list,res_list.net)
        return new_res_paginated

    def _split_by_alphabet(self,res_list,net):
        res_list.sort()
        if len(res_list)<=256:
            return [res_list]
        L=[]
        NX=int(math.ceil(len(res_list)/256.0))
        n=0
        x=1
        current=PaginationListByName(self,net,group_len=NX,group_seq=x)
        for res in res_list:
            if n>=256:
                L.append(current)
                x+=1
                n=0
                current=PaginationListByName(self,net,group_len=NX,group_seq=x)
            current.append(res)
            n+=1
        if current:
            L.append(current)
        return L
        
    def _split_by_subnet(self,res_list,net):
        res_list.sort()
        if len(res_list)<256: return [res_list]
        base_names=PaginationListByName(self,net)
        subnets={}
        for res in res_list:
            partial_name=res.name.strip(".").replace(net,"")
            if not partial_name:
                base_names.append(res)
                continue
            t=partial_name.split(".")
            if len(t)==1:
                base_names.append(res)
                continue
            sub=t[-1]
            if not subnets.has_key(sub):
                subnets[sub]=PaginationListByName(self,"."+sub+net)
            subnets[sub].append(res)
        ret=self._split_by_alphabet(base_names,net)
        for sub,s_res_list in subnets.items():
            ret+=self._split_by_subnet(s_res_list,"."+sub+net)
        return ret

class FileWrapper(object):
    def __init__(self,fname,default_mode='w'):
        self.fname=fname
        self.default_mode=default_mode
        self.fd=None

    def open(self,mode=''):
        if not mode: mode=self.default_mode
        self.fd=open(self.fname,mode)

    def write(self,txt):
        self.fd.write(txt)

    def close(self):
        self.fd.close()

################################################################################
################################################################################
###
### View
###
################################################################################
################################################################################


class GlobalView(object):
    sub_directories=[]

    def __init__(self,database,dirout):
        self.dirout=dirout
        self.database=database

    def _make_output_directories(self):
        for lab in self.sub_directories:
            try:
                os.makedirs(self.dirout+"/"+lab)
            except os.error, e:
                pass

    def _make_files(self):
        pass

    def output(self):
        self._make_output_directories()
        self._make_files()

##########################################################
#### Html

class ContextManager(object):
    def __init__(self,out_dir,root,static_root,theme,menus,logo_title):
        self.root=root
        self.static_root=static_root
        self.theme=theme
        self.menus=menus
        self.out_dir=out_dir
        self.logo_title=logo_title

        self.theme_dir=dns_config.THEMES_DIR+"/"+self.theme+"/templates"
        self.jinja_env=jinja2.Environment(loader=jinja2.FileSystemLoader(self.theme_dir),
                                          trim_blocks=True,lstrip_blocks=True)

        self.menus["single_db"]=[ (self.root+"/index.html","Indice"),
                                  (self.root+"/zones-index.html","Zone"),
                                  (self.root+"/ips-index.html","IP"),
                                  (self.root+"/names-index.html","Nomi"),
                                  (self.root+"/NS-index.html","NS"),
                                  (self.root+"/MX-index.html","MX"),
                                  (self.root+"/SRV-index.html","SRV"),
                                  (self.root+"/AFSDB-index.html","AFSDB"),
                                  (self.root+"/TXT-index.html","TXT"),
                                  (self.root+"/SPF-index.html","SPF") ]


    def _get_template(self,template_name):
        return self.jinja_env.get_template(template_name)

    def render(self,template,context_dict={}):
        template=self._get_template(template)
        context_dict["context_root"]=self.root
        context_dict["static_root"]=self.static_root
        context_dict["logo_title"]=self.logo_title
        for k,val in dns_config.HTML_BASE_VAR.items():
            context_dict[k.lower()]=val
        context_dict["menu_main"]=self.menus["main"]
        context_dict["menu_db"]=self.menus["single_db"]
        T=template.render(**context_dict)
        T=T.encode('utf-8')
        return T
        

class HtmlPage(FileWrapper):
    def __init__(self,fname,title,context_manager,toc_title=u""):
        self.context_manager=context_manager
        FileWrapper.__init__(self,self.context_manager.out_dir+"/"+fname)
        self.title=title
        self.url=self.context_manager.root+"/"+fname
        self.toc_title=toc_title
        if not self.toc_title: 
            self.toc_title=self.title

    def open(self,mode=''):
        FileWrapper.open(self)
        self._insert_template(TEMPLATES_HTML+"/header.html")

    def _insert_template(self,tname):
        ftempl=open(tname)
        for r in ftempl.readlines():
            r=r.replace("%%PAGE_TITLE%%",self.title)

            r=r.replace("%%CONTEXT_ROOT%%",self.context_manager.root)
            r=r.replace("%%STATIC_ROOT%%",self.context_manager.static_root)
            r=r.replace("%%LOGO_TITLE%%",self.context_manager.logo_title)
            for k,m_list in self.context_manager.menus.items():
                val=""
                for url,label in m_list:
                    val+='<a href="'+url+'">'+label+'</a>'
                r=r.replace("%%MENU_"+k.upper()+"%%",val)
            for k,val in HTML_BASE_VAR.items():
                r=r.replace("%%"+k+"%%",val)
            self.fd.write(r)
        ftempl.close()

    def script(self): 
        return ""

    def close(self):
        s=self.script()
        if s:
            self.write("<script>\n")
            self.write(s)
            self.write("\n</script>\n")
        self._insert_template(TEMPLATES_HTML+"/footer.html")
        FileWrapper.close(self)

    def new_cell(self,txt,td="td",cl="left",rowspan=1,colspan=1):
        t="<"+td+" class='"+cl+"'"
        if rowspan>1:
            t+=" rowspan='"+str(rowspan)+"'"
        if colspan>1:
            t+=" colspan='"+str(colspan)+"'"
        t+=">"+txt+"</"+td+">"
        return t

class HtmlPage2(FileWrapper):
    template_name=""

    def __init__(self,fname,title,context_manager,toc_title=u""):
        self.context_manager=context_manager
        FileWrapper.__init__(self,self.context_manager.out_dir+"/"+fname)
        self.title=unicode_convert(title)
        self.url=self.context_manager.root+"/"+fname
        self.toc_title=unicode_convert(toc_title)
        if not self.toc_title: 
            self.toc_title=self.title

    def _create_context(self):
        return {}

    def create(self):
        context=self._create_context()
        context["page_title"]=self.title
        T=self.context_manager.render(self.template_name,context)
        self.open(mode='w')
        self.write(T)
        self.close()

class HtmlIndexPage(HtmlPage2):
    template_name="index.html"

    def __init__(self,context_manager,list_subindexes,toc_title=u""):
        HtmlPage2.__init__(self,"index.html","Indice",context_manager,toc_title=toc_title)
        self.list_subindexes=list_subindexes

    def _create_context(self):
        return { "page_list": self.list_subindexes }

class HtmlSpecialIndexPage(HtmlPage):
    #template_name="special_index.html"
    def __init__(self,fname,title,context_manager,
                 special="",h_titles=["owner","views","ttl","data"],skip_empty=True,toc_title=u""):
        HtmlPage.__init__(self,fname,title,context_manager,toc_title=toc_title)
        self.h_titles=h_titles
        self.colspan=str(len(h_titles)+3)
        self.special=special
        self.skip_empty=skip_empty

    # def _create_context(self):
    #     ctx={
    #         "h_titles": self.h_titles
    #     }
    #     return ctx

    def open(self):
        HtmlPage.open(self)
        self.write("<center><table>\n")
        self.write("<thead>")
        self.write("<tr>")
        self.write("<th class='center' colspan='3'>zone</th>")
        for lab in self.h_titles:
            self.write("<th class='center'>"+lab+"</th>")
        self.write("</tr>\n")
        self.write("</thead>\n")

    def close(self):
        self.write("</table></center>\n")
        HtmlPage.close(self)


    def write_section_title(self,title):
        self.write("<thead><tr><th class='center' colspan='"+str(self.colspan)+"'>"+title+"</th></tr></thead>\n")

    ###
    def write_zone_row(self,zone_page):
        self.write(self.zone_index_row(zone_page)+"\n")

    def begin_zone_row(self,zone_page,rowspan=1):
        views=", ".join(map(str,list(zone_page.zone.merged_views_sets)))
        S="<tbody>"
        S+="<tr>"
        if zone_page.zone.is_reverse(): 
            S+=self.new_cell("R",td="th",rowspan=rowspan)
        else: 
            S+=self.new_cell("D",td="th",cl="center",rowspan=rowspan)
        S+=self.new_cell(str(zone_page.zone.id),td="th",cl="center",rowspan=rowspan)
        S+=self.new_cell('<a href="'+zone_page.url+'">'+zone_page.toc_title+'</a>',td="th",rowspan=rowspan)
        # S+=self.new_cell(zone_page.zone.classification,rowspan=rowspan)
        # S+=self.new_cell(views,rowspan=rowspan)
        return S

    def zone_index_row(self,zone_page):
        rowspan=0
        for r in zone_page.zone.special_records[self.special]:
            for view_list,rdata_list in r.merged:
                rowspan+=len(rdata_list)

        if rowspan==0:
            if self.skip_empty: 
                return ""
            S=self.begin_zone_row(zone_page,rowspan=rowspan)
            S+=self.new_cell('<i>none</i>',colspan=5)
            S+="</tr>\n"
            S+="</tbody>"
            return S

        S=self.begin_zone_row(zone_page,rowspan=rowspan)
        r_primo=True
        for r in zone_page.zone.special_records[self.special]:
            r_rowspan=0
            for view_set,rdata_list in r.merged:
                r_rowspan+=len(rdata_list)
            if r_primo:
                r_primo=False
            else:
                S+="<tr>"
            S+=self.new_cell(r.owner,rowspan=r_rowspan)
            v_primo=True    
            for view_set,rdata_list in r.merged:
                if v_primo:
                    v_primo=False
                else:
                    S+="<tr>"
                S+=self.new_cell(view_set.cell(),rowspan=len(rdata_list))
                # S+=self.new_cell(zone_page.zone.classifications_per_view_set[view_set],
                #                  rowspan=len(rdata_list))
                d_primo=True
                for rdata in rdata_list:
                    if d_primo:
                        d_primo=False
                    else:
                        S+="<tr>"
                    if rdata.ttl=="_":
                        S+=self.new_cell("")
                    else:
                        S+=self.new_cell(str(rdata.ttl))
                    S+=self.new_cell(" ".join(rdata.data))
                S+="</tr>\n"
            S+="</tr>\n"
        S+="</tbody>"
        return S


class HtmlZoneIndexPage(HtmlSpecialIndexPage):
    def __init__(self,context_manager,toc_title=""):
        HtmlSpecialIndexPage.__init__(self,"zones-index.html","Elenco zone",context_manager,
                                      toc_title=toc_title,
                                      h_titles=["records",
                                                "views","class.",
                                                "TTL",
                                                "primary master","email","serial number",
                                                "refresh","retry","expiry","nx. TTL"])

    def zone_index_row(self,zone_page):
        dns_type_list=list(zone_page.zone.dns_type_list)
        dns_type_list.sort()
        dns_types=", ".join(map(str,dns_type_list))

        S=self.begin_zone_row(zone_page,rowspan=len(zone_page.zone.merged_views_sets))
        S+=self.new_cell(dns_types,rowspan=len(zone_page.zone.merged_views_sets))
        primo=True
        for view_set in zone_page.zone.merged_views_sets:
            if primo: 
                primo=False
            else:
                S+='<tr>'
            for val in [view_set.cell(),
                        zone_page.zone.classifications_per_view_set[view_set],
                        zone_page.zone.get_ttl_by_view_set(view_set),
                        zone_page.zone.get_primary_master_by_view_set(view_set),
                        zone_page.zone.get_email_admin_by_view_set(view_set),
                        zone_page.zone.get_serial_number_by_view_set(view_set),
                        zone_page.zone.get_refresh_by_view_set(view_set),
                        zone_page.zone.get_retry_by_view_set(view_set),
                        zone_page.zone.get_expiry_by_view_set(view_set),
                        zone_page.zone.get_nx_ttl_by_view_set(view_set)]:
                S+=self.new_cell(str(val))
            S+="</tr>"

        S+="</tbody>"
        return S

class HtmlZonePage(HtmlPage2,ZoneOutputMethods):
    template_name="zone.html"

    def __init__(self,zone,context_manager,url_resolver,toc_title=""):
        fname="zones/zone_"+str(zone.id)+"_"+zone.name+".html"
        HtmlPage2.__init__(self,fname,zone.name,context_manager,toc_title=toc_title)
        self.zone=zone
        url_resolver.add_url(self.zone,self.url)
        for r in self.zone.def_rows+self.zone.rows:
            url_resolver.add_url(r,self.url+"#record"+str(r.id))

    def _create_context(self):
        views="; ".join(map(str,list(self.zone.merged_views_sets)))
        dns_type_list=list(self.zone.dns_type_list)
        dns_type_list.sort()
        dns_types=", ".join(map(str,dns_type_list))
        ctx={
            "zone": self.zone,
            "views": views,
            "dns_types": dns_types,
            "is_reverse": self.zone.is_reverse(),
        }
        V=list(self.zone.merged_views_sets)
        if self.zone.reduced=="single_view":
            ctx["views"]=V[0][0].name
        elif self.zone.reduced!="multiple":
            ctx["views"]=", ".join(map(lambda v: v.name,V[0]))
        else:
            ctx["views"]=[]
            for view_set in self.zone.merged_views_sets:
                ctx["views"].append( (view_set.cell(),self.zone.classifications_per_view_set[view_set]) )

        ctx["zone_texts"]=[]
        for view_set,txt in self.zone_txt_multiple():
            ctx["zone_texts"].append( (view_set.cell(),txt) )
        ctx["rows"]=[]
        for row in self.zone.def_rows+self.zone.rows:
            r_rowspan=0
            for view_set,rdata_list in row.merged:
                r_rowspan+=len(rdata_list)
            drow={
                "id": row.id,
                "dns_class": row.dns_class,
                "dns_type": row.dns_type.dns_type,
                "owner": row.owner,
                "rowspan": r_rowspan,
                "merged": []
            }
            for view_set,rdata_list in row.merged:
                view_set_cell=view_set.cell()
                classification=row.classifications_per_view_set[view_set]
                rdata_list_new=[]
                for rdata in rdata_list:
                    rdata_list_new.append({"ttl": rdata.ttl, "data": " ".join(rdata.data) })
                drow["merged"].append( (view_set_cell,len(rdata_list),classification,rdata_list_new) )
            ctx["rows"].append(drow)
        return ctx

class HtmlSublistPage(HtmlPage2):
    template_name="sublist.html"

    def __init__(self,fname,title,context_manager,res_list):
        toc_title=str(res_list)+" "+res_list.title_add()
        super(HtmlSublistPage,self).__init__(fname,title+": "+toc_title,context_manager,
                                             toc_title=toc_title)
        self.next=None
        self.up=None
        self.previous=None
        self.res_list=res_list

    def _create_context(self):
        ctx={
            "previous": self.previous,
            "next": self.next,
            "up": self.up,
            "table_header": self.res_list.table_header_ctx(),
            "template_row_name": self.res_list.template_row_name
        }
        ctx["res_list"]=[]

        for row in self.res_list:
            q=self.res_list.html_row_ctx(row)
            ctx["res_list"].append(q)
        
        return ctx


    def size(self): 
        """ Il numero di oggetti.
        
        :return: Lunghezza di self.res_list (PaginationList). """
        return len(self.res_list)

    def toc_row(self):
        """ Costruisce la riga nella tabella indice dell'HtmlListPage madre di questa.

        Utilizza i metodi di res_list:

        * toc_title_cells()
        * toc_size_cells()
        * toc_range_cells()

        che ritornano una stringa con una o più celle (td) in html.
        
        :return: Una riga formata dalle celle di self.res_list. """

        h1=self.res_list.toc_title_cells()
        h2=self.res_list.toc_size_cells()
        h3=self.res_list.toc_range_cells()
        S=h1+h2+h3

        L=len(S)
        tab=Table(1,L)
        tab.set_row(0,S)
        tab.set_row_data(0, [ ("href",self.url) ] )
            
        return tab

    def known_vlan(self): return self.res_list.known_vlan()

class HtmlListPage(HtmlPage2):
    template_name="list.html"

    def __init__(self,fname,title,context_manager,subdir,subprefix,res_list,toc_title=""):
        super(HtmlListPage,self).__init__(fname,title,context_manager,toc_title=toc_title)
        self.sublist_pages=[]
        self.subprefix=subprefix
        self.subdir=subdir
        self.res_list=res_list

    def new_sublist_page(self,title,res_sublist):
        """ Genera una nuova pagina per le sublist e la aggiunge all'elenco delle pagine (self.sublist_pages).

        :param title: Titolo della pagina.
        :param res_sublist: Un oggetto di classe PaginationList (o figlia).

        :return: Un oggetto HtmlSublistPage per la visualizzazione di res_sublist.
        """

        ind=len(self.sublist_pages)

        new_page=HtmlSublistPage(self.subdir+"/"+self.subprefix+"-"+("%04d" % ind)+".html",
                                 title,self.context_manager,res_sublist)
        if ind!=0: 
            new_page.previous=self.sublist_pages[-1]
            self.sublist_pages[-1].next=new_page
        new_page.up=self
        self.sublist_pages.append(new_page)
        return new_page

    def _create_context(self):
        ctx={
            "table_header": self.res_list.header_table(),
        }
        ctx["table_rows"]=[]
        for pag in self.sublist_pages:
            row=pag.toc_row()
            print unicode_convert(row)
            ctx["table_rows"].append(row)
        return ctx
    

class HtmlView(GlobalView):
    sub_directories=[ "zones","ips","names" ]
    special_records=[ "NS","MX","SRV","AFSDB","TXT","SPF" ]

    def __init__(self,database,context_manager,vlan_manager,labelers={}):
        GlobalView.__init__(self,database,context_manager.out_dir)

        self.labelers=labelers
        self.vlan_manager=vlan_manager
        self.context_manager=context_manager
        self.url_resolver=UrlResolver()
    
    def _make_files(self):
        dns_db=self.database
        P=[]
        for v in dns_db.views:
            P.append( (str(v),dns_db.zones_by_views[v.id]) )
        P.append( ("Merged",dns_db.zones_multiple_merged) )
        P.append( ("Multiple",dns_db.zones_multiple_views) )

        other_indexes=[]

        other_indexes.append(HtmlZoneIndexPage(self.context_manager))

        for t in self.special_records:
            other_indexes.append(HtmlSpecialIndexPage(t+"-index.html","Elenco "+t.upper(),
                                                      self.context_manager,special=t))

        for hpage in other_indexes: hpage.open()

        for v,zlist in P:
            for hpage in other_indexes:
                hpage.write_section_title(str(v))
            for z in zlist:
                zone_page=HtmlZonePage(z,self.context_manager,self.url_resolver)
                zone_page.create()
                for hpage in other_indexes:
                    hpage.write_zone_row(zone_page)

        for hpage in other_indexes: hpage.close()

        pag_ip=PaginationByIp(dns_db.res_ips,PAGINATION,self.url_resolver,self.vlan_manager)
        pag_name=PaginationByName(dns_db.res_names,PAGINATION,self.url_resolver)
        if self.labelers.has_key("ip"):
            pag_ip.labelers+=self.labelers["ip"]
        if self.labelers.has_key("name"):
            pag_name.labelers+=self.labelers["name"]

        elenco_ip=self._build_elenco("ips","IP",pag_ip,dns_db)
        elenco_nomi=self._build_elenco("names","Nomi",pag_name,dns_db)

        elenco_ip.create()
        elenco_nomi.create()

        index_html=HtmlIndexPage(self.context_manager,[elenco_ip,elenco_nomi]+other_indexes)
        index_html.create()


    def _build_elenco(self,prefix,title,res_list,dns_db):
        res_paginated=res_list.paginate()

        index_html=HtmlListPage(prefix+"-index.html",title,self.context_manager,
                                prefix,prefix,res_list)

        for L in res_paginated:
            if not L and not L.known_vlan():
                continue
            new_sub_page=index_html.new_sublist_page(title,L)
            for res in L:
                self.url_resolver.add_url(res,new_sub_page.url+"#res"+str(res.id))

        return index_html

    
################################################################################
################################################################################
###
### Configuration
###
################################################################################
################################################################################


class ViewFile(FileWrapper):
    def __init__(self,name,order,outdir,
                 description=[],
                 match_clients=["any"],
                 recursion=False):
        self.name=name
        self.order=order
        self.outdir=outdir
        self.description=""
        self.match_clients=match_clients
        self.recursion=recursion
        self.basename=("%03d" % order)+"_"+name+".view"
        FileWrapper.__init__(self,outdir+"/"+self.basename)

    def open(self,mode=''):
        FileWrapper.open(self)
        self.write("/***\n\n")
        self.write("    View "+self.name+"\n\n")
        if self.description:
            for r in self.description:
                self.write("    "+r+"\n")
            self.write("\n")
        self.write("***/\n\n")
        self.write('view "'+self.name+'" {\n')
        if self.match_clients:
            self.write('    match-clients { '+";".join(self.match_clients)+'; };\n')
        else:
            self.write('    match-clients { any; };\n')
        if self.recursion:
            self.write('    recursion yes;\n\n')
        else:
            self.write('    recursion no;\n\n')

        self.write('    zone "." IN {\n')
        self.write('        type hint;\n')
        self.write('        file "/var/named/named.ca";\n')
        self.write('    };\n\n')
        self.write('    include "/etc/named.rfc1912.zones";\n\n')

    def close(self,mode=''):
        self.write('};\n')
        FileWrapper.close(self)

    def write_zone(self,zone,target_fname):
        self.write('    zone "'+zone.name+'" {\n')
        self.write('        type master;\n')
        self.write('        file "/var/named/'+target_fname+'";\n')
        self.write('    };\n\n')

    def __eq__(self,other):
        return ( (self.order==other.order) and (self.name==other.name) )
    
    def __lt__(self,other):
        if self.order<other.order: return True        
        if self.order>other.order: return False
        return self.name < other.name

    def __ne__(self,other): return not self.__eq__(other)

    def __le__(self,other):
        if self.__eq__(other): return True
        return self.__lt__(other)
        
    def __gt__(self,other): return other.__lt__(self)

    def __ge__(self,other):
        if self.__eq__(other): return True
        return self.__gt__(other)

class ViewFileFallback(ViewFile):
    def __init__(self,outdir):
        self.outdir=outdir
        ViewFile.__init__(self,"fallback",999,outdir,
                             description=["Quando non ne trova una da assegnare al client sceglie questa."],
                             match_clients=["any"],
                             recursion=False)

    def create(self):
        self.open()
        self.close()

class ViewFileIndex(FileWrapper):
    def __init__(self,outdir):
        self.outdir=outdir
        FileWrapper.__init__(self,outdir+"/000_index.conf")
        self.view_files=[]

    def open(self,mode=''):
        FileWrapper.open(self)
        self.write("/***\n\n")
        self.write("    Indice delle viste caricate\n\n")
        self.write("***/\n\n")
        fback=ViewFileFallback(self.outdir)
        fback.create()
        self.view_files.append(fback)

    def create(self):
        self.open()
        self.view_files.sort()
        for fv in self.view_files:
            self.write('include "/etc/named/views/'+fv.basename+'";\n')
        self.close()

class ZoneFile(FileWrapper,ZoneOutputMethods):
    def __init__(self,zone,outdir):
        FileWrapper.__init__(self,outdir+"/"+zone.name)
        self.zone=zone
        self.outdir=outdir

    def open(self,mode=''):
        try:
            os.makedirs(self.outdir)
        except os.error, e:
            pass
        FileWrapper.open(self)

    def close(self,mode=''):
        FileWrapper.close(self)

    def create(self):
        view_set,txt=self.zone_txt_multiple()[0]
        self.open()
        self.write(txt)
        self.close()

class ZoneFileMultiple(ZoneFile):
    def __init__(self,zone,outdir,view_set):
        ZoneFile.__init__(self,zone,outdir)
        self.view_set=view_set

    def create(self):
        self.open()
        for view_set,txt in self.zone_txt_multiple():
            if view_set!=self.view_set: continue
            self.write(txt)
        self.close()


### non deve mappare nuove viste con vecchie, ma considerare solo le vecchie; la logica va spostata in un filtro

class ConfView(GlobalView):
    sub_directories=[ "zones","views" ]
    zones_directory="zones"
    target_context="/var/named"

    def __init__(self,database,dirout,views_params={}):
        GlobalView.__init__(self,database,dirout)
        self.views_params=views_params
    
    def _zone_dirnames_per_view_set(self,zone):
        R={}
        base_dirname=self._zone_base_dirname(zone)
        for view_set in zone.merged_views_sets:
            v_out_dir=base_dirname+"/"+zone.classifications_per_view_set[view_set]+"/"+view_set.label
            R[view_set]=v_out_dir
        return R.items()

    def _zone_dirname_by_view(self,zone,view): 
        base_dirname=self._zone_base_dirname(zone)
        for view_set in zone.merged_views_sets:
            if not view_set.has_view(view): continue
            v_out_dir=base_dirname+"/"+zone.classifications_per_view_set[view_set]+"/"+view_set.label
            return v_out_dir
        return None

    def _zone_dirname(self,zone):
        suffix="/"+zone.classification
        if suffix=="mixed":
            views="_".join(map(lambda x: x.name,zone.views_list))
            suffix+="/"+views
        return self._zone_base_dirname(zone)+suffix

    def _zone_base_dirname(self,zone):
        prefix="zones/"
        if zone.reduced=="multiple":
            if zone.is_reverse():
                return prefix+"multiple_reverse"
            return prefix+"multiple"
        if zone.is_reverse():
            return prefix+"common_reverse"
        return prefix+"common"
        
    def _zone_target_filename_by_view(self,zone,view):
        if zone.reduced!="multiple":
            out_dir=self._zone_dirname(zone)
        else:
            out_dir=self._zone_dirname_by_view(zone,view)
        if not out_dir: return None
        return self.target_context+"/"+out_dir+"/"+zone.name

    def _out_conf_zone(self,zone):
        for view in zone.views_list:
            self.view_files[view.name].write_zone(zone,self._zone_target_filename_by_view(zone,view))

        if zone.reduced!="multiple":
            out_dir=self._zone_dirname(zone)
            zfile=ZoneFile(zone,self.dirout+"/"+out_dir)
            zfile.create()
            return

        for view_set,v_out_dir in self._zone_dirnames_per_view_set(zone):
            zfile=ZoneFileMultiple(zone,self.dirout+"/"+v_out_dir,view_set)
            zfile.create()

    def _build_index_conf(self,dns_db):
        self.view_files={}
        view_new_index=ViewFileIndex(self.dirout)

        base_order=10+max(map(lambda x: x["order"],
                              filter(lambda x: x.has_key("order"),self.views_params.values())))

        for view in dns_db.views:
            lab=view.name
            if self.views_params.has_key(view.name) and self.views_params[view.name].has_key("order"):
                order=self.views_params[view.name]["order"]
            else:
                order=base_order
                base_order+=10
            self.view_files[lab]=ViewFile(lab,order,self.dirout)
            self.view_files[lab].open()
            view_new_index.view_files.append(self.view_files[lab])

        view_new_index.create()

    def _make_files(self):
        dns_db=self.database
        self._build_index_conf(dns_db)

        for v in dns_db.views:
            for z in dns_db.zones_by_views[v.id]:
                self._out_conf_zone(z)

        for z in dns_db.zones_multiple_merged:
            self._out_conf_zone(z)

        for z in dns_db.zones_multiple_views:
            self._out_conf_zone(z)

        for vf in self.view_files.values(): vf.close()


class IpListView(object):
    def __init__(self,database,fname):
        self.fname=fname
        self.database=database

    def output(self):
        dns_db=self.database
        fd=open(self.fname,"w")
        for res in dns_db.res_ips:
            fd.write(res.ip+"\n")
        fd.close()
