import sys,re
import os,datetime
import shutil

from dinosaurus_lib.config import *

class ZoneOutputMethods(object):
    record_skip=["WINS"]
    record_pass=["MX","NS","A","CNAME","PTR","AAAA","TXT","SPF","HINFO","AFSDB","SRV" ]
    record_rebuild=["SOA"]
    record_format="%-20s %-6.6s %-2.2s %-5.5s"

    ### QUIMZ Deve stampare i dati reali non quelli futuri
    def zone_txt_header(self):
        # @                                               IN      SOA     ns01.regione.veneto.it. nsmaster.regione.veneto.it.     (
        #         2015062603      ; serial
        #         86400           ; refresh
        #         1800            ; retry
        #         2592000         ; expire
        #         86400                   ); minimum TTL

        T='$TTL '+self.zone.get_ttl()+'\n'
        t_format=self.record_format

        T+=t_format % ("@","","","SOA")

        T+=' '+PRIMARY_MASTER+' '+EMAIL_ADMIN+' (\n'

        indent=t_format % ("","","","")
        indent+="".join(map(lambda x: " ",range(0,len(PRIMARY_MASTER))))
        indent+=" "

        for val,lab in [ (SERIAL_NUMBER,"serial number"),
                         (self.zone.get_refresh(),"refresh"),
                         (self.zone.get_retry(),"retry"),
                         (self.zone.get_expiry(),"expiry"),
                         (self.zone.get_nx_ttl(),"nxdomain TTL") ]:
            T+=indent
            T+='%-12s ; %s\n' % (str(val),lab)
        T+=indent
        T+=')\n'
        return T

    def zone_txt_simple(self):
        T=self.zone_txt_header()
        for r in self.zone.def_rows:
            T+=self.record_txt_simple(r)
        for r in self.zone.rows:
            T+=self.record_txt_simple(r)
        return T+"\n\n"

    def zone_txt_multiple(self):
        H=self.zone_txt_header()
        T={}
        for vlabel in self.zone.get_merged_views_labels():
            T[vlabel]=H
        for r in self.zone.def_rows:
            for label,txt in self.record_txt_multiple(r):
                T[label]+=txt
        for r in self.zone.rows:
            for label,txt in self.record_txt_multiple(r):
                T[label]+=txt
        for k in T.keys():
            T[k]+="\n\n"
        return T.items()

    def format_record(self,record,rdata,owner=True):
        t_format=self.record_format+" %s\n"
        if owner:
            rec_owner=record.get_owner()
        else:
            rec_owner=""
        return t_format % (rec_owner,record.get_ttl(rdata.ttl),record.get_dns_class(),
                           record.get_dns_type(),record.get_data(rdata.data))

    def record_txt_simple(self,record):
        if record.dns_type.dns_type in self.record_skip: return ""
        if record.dns_type.dns_type in self.record_rebuild: return ""
        T=""
        primo=True
        for view_list,rdata_list in record.merged:
            for rdata in rdata_list:
                T+=self.format_record(record,rdata,owner=primo)
                primo=False
        return T

    def record_txt_multiple(self,record):
        if record.dns_type.dns_type in self.record_skip: return []
        if record.dns_type.dns_type in self.record_rebuild: return []
        T={}
        for view_list,rdata_list in record.merged:
            primo=True
            label="_".join(map(lambda x: x.name,view_list))
            if not T.has_key(label): T[label]=""
            for rdata in rdata_list:
                T[label]+=self.format_record(record,rdata,owner=primo)
                primo=False
        return T.items()


class Pagination(object):
    def __init__(self,res_list,object_per_page):
        self.res_list=res_list
        self.object_per_page=object_per_page

    def paginate(self):
        res_paginated=[]
        n=0
        L=[]
        for r in self.res_list:
            L.append(r)
            if n<PAGINATION:
                n+=1
                continue
            res_paginated.append(L)
            n=0
            L=[]
        if L:
            res_paginated.append(L)
        return res_paginated

class PaginationByIp(Pagination):
    def paginate(self):
        res_paginated=[]
        n=0
        L=[]
        current_net=""
        no_net=[]
        for r in self.res_list:
            t=r.ip.split(".")
            if len(t)!=4: 
                no_net.append(r)
                continue
            net=".".join(t[:3])
            if current_net==net:
                L.append(r)
                continue
            res_paginated.append(L)
            L=[]
            L.append(r)
            current_net=net
        if L:
            res_paginated.append(L)
        if no_net:
            res_paginated.append(no_net)
        return res_paginated

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

class GlobalView(object):
    sub_directories=[]

    def __init__(self,dirout):
        self.dirout=dirout

    def _make_output_directories(self):
        for lab in self.sub_directories:
            try:
                os.makedirs(self.dirout+"/"+lab)
            except os.error, e:
                pass

    def make_files(self,dns_db):
        pass

    def output(self,dns_db):
        self._make_output_directories()
        self.make_files(dns_db)

################################################################################
################################################################################
###
### Html
###
################################################################################
################################################################################

class HtmlPage(FileWrapper):
    def __init__(self,fname,title,base_dir,out_dir):
        self.title=title
        self.base_dir=base_dir
        self.out_dir=out_dir
        FileWrapper.__init__(self,out_dir+"/"+fname)
        self.url="./"+fname

    def open(self,mode=''):
        FileWrapper.open(self)
        self.insert_template(TEMPLATES_HTML+"/header.html")

    def insert_template(self,tname):
        ftempl=open(tname)
        for r in ftempl.readlines():
            r=r.replace("%%PAGE_TITLE%%",self.title)
            r=r.replace("%%BASE_DIR%%",self.base_dir)
            self.fd.write(r)
        ftempl.close()

    def close(self):
        self.insert_template(TEMPLATES_HTML+"/footer.html")
        FileWrapper.close(self)

    def new_cell(self,txt,td="td",cl="left",rowspan=1,colspan=1):
        t="<"+td+" class='"+cl+"'"
        if rowspan>1:
            t+=" rowspan='"+str(rowspan)+"'"
        if colspan>1:
            t+=" colspan='"+str(colspan)+"'"
        t+=">"+txt+"</"+td+">"
        return t

class HtmlIndexPage(HtmlPage):
    def __init__(self,out_dir):
        HtmlPage.__init__(self,"index.html","Indice",".",out_dir)
        self.list_subindexes=[ ('./zones-index.html',"Elenco zone"),
                               ('./ips-index.html',"Elenco IP"),
                               ('./names-index.html',"Elenco Nomi") ]

    def create(self):
        self.open()
        self.write("<ul>")
        for url,title in self.list_subindexes:
            self.write("<li><a href='"+url+"'>"+title+"</a></li>")
        self.write("</ul>")
        self.close()

class HtmlSpecialIndexPage(HtmlPage):
    def __init__(self,fname,title,out_dir,special="",h_titles=["class.","views","owner","views","ttl","data"]):
        HtmlPage.__init__(self,fname,title,".",out_dir)
        self.h_titles=h_titles
        self.colspan=str(len(h_titles)+3)
        self.special=special
        

    def open(self):
        HtmlPage.open(self)
        self.write("<center><table>\n")
        self.write("<tr>")
        self.write("<tr>")
        self.write("<th class='center' colspan='3'>zone</th>")
        for lab in self.h_titles:
            self.write("<th class='center'>"+lab+"</th>")
        self.write("</tr>\n")

    def close(self):
        self.write("</table></center>\n")
        HtmlPage.close(self)

    def write_section_title(self,title):
        self.write("<tr><th class='center' colspan='"+str(self.colspan)+"'>"+title+"</th></tr>\n")

    def write_zone_row(self,zone):
        self.write(self.zone_index_row(zone)+"\n")

    def begin_zone_row(self,zone,rowspan=1):
        views=", ".join(map(str,list(zone.views_set())))
        S="<tbody>"
        S+="<tr>"
        if zone.is_reverse(): 
            S+=self.new_cell("R",td="th",rowspan=rowspan)
        else: 
            S+=self.new_cell("D",td="th",cl="center",rowspan=rowspan)
        S+=self.new_cell(str(zone.id),td="th",cl="center",rowspan=rowspan)
        S+=self.new_cell('<a href="'+zone.get_url()+'">'+zone.name+'</a>',td="th",rowspan=rowspan)
        S+=self.new_cell(zone.classification(),rowspan=rowspan)
        S+=self.new_cell(views,rowspan=rowspan)
        return S

    def zone_index_row(self,zone):
        rowspan=0
        for r in zone.special_records[self.special]:
            for view_list,rdata_list in r.merged:
                rowspan+=len(rdata_list)

        S=self.begin_zone_row(zone,rowspan=rowspan)
        if rowspan==0:
            S+=self.new_cell('<i>none</i>',colspan=4)
            S+="</tr>\n"
            S+="</tbody>"
            return S
        primo=True
        for r in zone.special_records[self.special]:
            for view_list,rdata_list in r.merged:
                views=",".join(map(str,view_list))
                for rdata in rdata_list:
                    if primo:
                        primo=False
                    else:
                        S+="<tr>"
                    S+=self.new_cell(r.get_owner())
                    S+=self.new_cell(views)
                    if rdata.ttl=="_":
                        S+=self.new_cell("")
                    else:
                        S+=self.new_cell(str(rdata.ttl))
                    S+=self.new_cell(str(rdata.data))
                S+="</tr>\n"
            S+="</tr>\n"
        S+="</tbody>"
        return S


class HtmlZoneIndexPage(HtmlSpecialIndexPage):
    def __init__(self,out_dir):
        HtmlSpecialIndexPage.__init__(self,"zones-index.html","Elenco zone",out_dir,
                                      ["class.","views","records","default_ttl",
                                       "name_server","email_addr","serial_number",
                                       "refresh","retry","expiry","nx_ttl"])
    def zone_index_row(self,zone):
        dns_type_list=list(zone.dns_type_list)
        dns_type_list.sort()
        dns_types=", ".join(map(str,dns_type_list))

        S=self.begin_zone_row(zone)
        S+=self.new_cell(dns_types,rowspan=2)
        for k in [ "default_ttl",
                   "name_server",
                   "email_addr",
                   "serial_number",
                   "refresh",
                   "retry",
                   "expiry",
                   "nx_ttl" ]:
            S+=self.new_cell(str(zone.soa_record.data[k]))
        S+="</tr>\n"
        S+="<tr>"
        for k in [ zone.get_ttl(),
                   PRIMARY_MASTER,
                   EMAIL_ADMIN,
                   SERIAL_NUMBER,
                   zone.get_refresh(),
                   zone.get_retry(),
                   zone.get_expiry(),
                   zone.get_nx_ttl() ]:
            if type(k)!=list:
                S+=self.new_cell(k)
                continue
            S+=self.new_cell(k,"left evidenzia")
            
        S+="</tr>"
        S+="</tbody>"
        return S

class HtmlZonePage(HtmlPage,ZoneOutputMethods):
    def __init__(self,zone,out_dir):
        fname="zones/zone_"+str(zone.id)+"_"+zone.name+".html"
        HtmlPage.__init__(self,fname,str(zone),"..",out_dir)
        self.zone=zone

    def create(self):
        views=", ".join(map(str,list(self.zone.views_set())))
        dns_type_list=list(self.zone.dns_type_list)
        dns_type_list.sort()
        dns_types=", ".join(map(str,dns_type_list))
        cl=self.zone.classification()
        if self.zone.is_reverse():
            cl+=", reverse"
        cl+=", "+self.zone.reduced

        self.open()

        self.write("<p>"+cl+"</p>\n")
        self.write("<p>views: "+views+"</p>\n")
        self.write("<p>record types: "+dns_types+"</p>\n")
        self.write("<p>views set:</p>\n<url>")

        cl_views=self.zone.classification_by_view()

        for vtuple in self.zone.merged_views_sets():
            label="_".join(map(lambda x: x.name,vtuple))
            self.write("<li>")
            self.write(", ".join(map(str,vtuple)))
            self.write(" ("+cl_views[label]+")")
            self.write("</li>\n")
        self.write("</url>\n")

        if self.zone.reduced=="multiple":
            for label,txt in self.zone_txt_multiple():
                self.write("<p><b>"+label+"</b></p>\n")
                self.write("<pre>\n")
                self.write(txt)
                self.write("</pre>\n")
        else:
            self.write("<pre>\n")
            self.write(self.zone_txt_simple())
            self.write("</pre>\n")

        self.write("<center><table>\n")

        ### QUI x4

        for r in self.zone.def_rows:
            self.write(self._html_row(r)+"\n")
        for r in self.zone.rows:
            self.write(self._html_row(r)+"\n")

        self.write("</table></center>\n")
        self.close()

    def _html_row(self,row):
        S="<tbody>"
        S+="<tr>"
        S+=self.new_cell(row.dns_class+" "+row.dns_type.dns_type)
        S+=self.new_cell(row.classification())
        S+=self.new_cell(row.owner,td="th",colspan=3)
        S+="</tr>\n"

        for view_list,rdata_list in row.merged:
            views=",".join(map(str,view_list))
            for rdata in rdata_list:
                s="<tr>"
                s+=self.new_cell("",colspan=2)
                s+=self.new_cell(views)
                if rdata.ttl=="_":
                    s+=self.new_cell("")
                else:
                    s+=self.new_cell(str(rdata.ttl))
                s+=self.new_cell(str(rdata.data))
                s+="</tr>\n"
                S+=s
            return s

        S+="</tbody>"
        return S



class HtmlSublistPage(HtmlPage):
    def __init__(self,fname,title,out_dir,res_list):
        super(HtmlSublistPage,self).__init__(fname,title,"..",out_dir)
        self.next=None
        self.up=None
        self.previous=None
        self.res_list=res_list

    def _write_pagination(self):
        self.write('<p>')
        if self.previous: self.write(' <a href=".'+self.previous.url+'">previous</a>')
        if self.up:       self.write(' <a href=".'+self.up.url+'">up</a>')
        if self.next:     self.write(' <a href=".'+self.next.url+'">next</a>')
        self.write('</p>')

    def open(self):
        HtmlPage.open(self)
        self._write_pagination()
        self.write("<center><table>\n")

    def close(self):
        self.write("</table></center>\n")
        self._write_pagination()
        HtmlPage.close(self)

    def create(self):
        self.open()
        self.write(self.res_list[0].table_header()+"\n")
        for r in self.res_list:
            self.write(r.html_row()+"\n")
        self.close()

class HtmlListPage(HtmlPage):
    def __init__(self,fname,title,out_dir,subdir,subprefix):
        super(HtmlListPage,self).__init__(fname,title,".",out_dir)
        self.sublist_pages=[]
        self.subprefix=subprefix
        self.subdir=subdir

    def new_sublist_page(self,title,res_sublist):
        ind=len(self.sublist_pages)
        new_page=HtmlSublistPage(self.subdir+"/"+self.subprefix+"-"+("%04d" % ind)+".html",
                                 title,self.out_dir,res_sublist)
        if ind!=0: 
            new_page.previous=self.sublist_pages[-1]
            self.sublist_pages[-1].next=new_page
        new_page.up=self
        self.sublist_pages.append(new_page)

    def create(self):
        self.open()
        self.write("<ul>")
        for sub in self.sublist_pages:
            self.write("<li><a href='"+sub.url+"'>"+sub.title+"</a></li>")
            sub.create()
        self.write("</ul>")
        self.close()
    

class HtmlView(GlobalView):
    sub_directories=[ "zones","ips","names" ]
    special_records=[ "NS","MX","SRV","AFSDB","TXT","SPF" ]
    css_list=[ ("dns.css","dns.css") ]

    def make_files(self,dns_db):
        P=[]
        for v in dns_db.views:
            P.append( (str(v),dns_db.zones_by_views[v.id]) )
        P.append( ("Merged",dns_db.zones_multiple_merged) )
        P.append( ("Multiple",dns_db.zones_multiple_views) )

        try:
            os.makedirs(self.dirout+"/css")
        except os.error, e:
            pass

        for templ,dest in self.css_list:
            shutil.copyfile(TEMPLATES_CSS+"/"+templ,self.dirout+"/css/"+dest)

        index_html=HtmlIndexPage(self.dirout)
        other_indexes=[]
        other_indexes.append(HtmlZoneIndexPage(self.dirout))

        for t in self.special_records:
            index_html.list_subindexes.append( ("./"+t+"-index.html","Elenco "+t.upper()) )
            other_indexes.append(HtmlSpecialIndexPage(t+"-index.html","Elenco "+t.upper(),self.dirout,special=t))

        index_html.create()
        for hpage in other_indexes: hpage.open()

        for v,zlist in P:
            for hpage in other_indexes:
                hpage.write_section_title(str(v))
            for z in zlist:
                for hpage in other_indexes:
                    hpage.write_zone_row(z)
                zone_file=HtmlZonePage(z,self.dirout)
                zone_file.create()

        for hpage in other_indexes: hpage.close()

        self._stampa_elenco("ips","Elenco IP",".",PaginationByIp(dns_db.res_ips,PAGINATION))
        self._stampa_elenco("names","Elenco nomi",".",Pagination(dns_db.res_names,PAGINATION))


    def _stampa_elenco(self,prefix,title,base,res_list):
        res_paginated=res_list.paginate()

        index_html=HtmlListPage(prefix+"-index.html",title,self.dirout,prefix,prefix)

        for L in res_paginated:
            if not L: continue
            sub_title=str(L[0])+" - "+str(L[-1])
            index_html.new_sublist_page(title+" "+sub_title+" ("+str(len(L))+")",L)

        index_html.create()
    
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
        self.basename=str(order)+"_"+name+".view"
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
        ViewFile.__init__(self,"fallback",99,outdir,
                             description=["Quando non ne trova una da assegnare al client sceglie questa."],
                             match_clients=["any"],
                             recursion=False)

    def create(self):
        self.open()
        self.close()

class ViewFileIndex(FileWrapper):
    def __init__(self,outdir):
        self.outdir=outdir
        FileWrapper.__init__(self,outdir+"/00_index.conf")
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
        self.write('include "/etc/named/views/99_fallback.view";\n')
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
        self.open()
        self.write(self.zone_txt_simple())
        self.close()

class ZoneFileMultiple(ZoneFile):
    def __init__(self,zone,outdir,vlabel):
        ZoneFile.__init__(self,zone,outdir)
        self.vlabel=vlabel

    def create(self):
        self.open()
        for vlabel,txt in self.zone_txt_multiple():
            if vlabel!=self.vlabel: continue
            self.write(txt)
        self.close()

class ConfView(GlobalView):
    sub_directories=[ "zones","views" ]
    zones_directory="zones"
    target_context="/var/named"
    
    def _build_index_conf(self,dirout):
        self.view_files={}
        view_new_index=ViewFileIndex(dirout)

        for order,lab in [ (10,"private_intranet"),
                           (80,"public_internet"),
                           (70,"public_guest"),
                           (60,"public_extranet") ]:
            self.view_files[lab]=ViewFile(lab,order,dirout)
            self.view_files[lab].open()
            view_new_index.view_files.append(self.view_files[lab])

        view_new_index.create()

        self.view_map_to_new={
            "any":     self.view_files["public_internet"],
            "guest":   self.view_files["public_guest"],
            "extra":   self.view_files["public_extranet"],
            "windows": self.view_files["private_intranet"],
            "intra":   self.view_files["private_intranet"],
        }

    def make_files(self,dns_db):
        self._build_index_conf(self.dirout)

        for v in dns_db.views:
            for z in dns_db.zones_by_views[v.id]:
                self.out_conf_zone(z)

        for z in dns_db.zones_multiple_merged:
            self.out_conf_zone(z)

        for z in dns_db.zones_multiple_views:
            self.out_conf_zone(z)

        for vf in self.view_files.values(): vf.close()


    def zone_dirnames_per_vlabel(self,zone):
        R={}
        base_dirname=self._zone_base_dirname(zone)
        cl_views=zone.classification_by_view()
        for vlabel in zone.get_merged_views_labels():
            v_out_dir=base_dirname+"/"+cl_views[vlabel]+"/"+vlabel
            R[vlabel]=v_out_dir
        return R.items()

    def zone_dirname_by_view(self,zone,view_name): 
        base_dirname=self._zone_base_dirname(zone)
        cl_views=zone.classification_by_view()
        for vtuple in zone.merged_views_sets():
            if view_name not in map(lambda v: v.name,vtuple): continue
            vlabel="_".join(map(lambda x: x.name,vtuple))
            v_out_dir=base_dirname+"/"+cl_views[vlabel]+"/"+vlabel
            return v_out_dir
        return None

    def zone_dirname(self,zone):
        suffix="/"+zone.classification()
        if suffix=="mixed":
            views="_".join(map(lambda x: x.name,list(zone.views_set())))
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
        
    def zone_target_filename_by_view(self,zone,view_name):
        if zone.reduced!="multiple":
            out_dir=self.zone_dirname(zone)
        else:
            out_dir=self.zone_dirname_by_view(zone,view_name)
        if not out_dir: return None
        return self.target_context+"/"+out_dir+"/"+zone.name

    def out_conf_zone(self,zone):
        for view in zone.views_set():
            vname=view.name
            self.view_map_to_new[vname].write_zone(zone,self.zone_target_filename_by_view(zone,vname))

        if zone.reduced!="multiple":
            out_dir=self.zone_dirname(zone)
            zfile=ZoneFile(zone,self.dirout+"/"+out_dir)
            zfile.create()
            return

        for vlabel,v_out_dir in self.zone_dirnames_per_vlabel(zone):
            zfile=ZoneFileMultiple(zone,self.dirout+"/"+v_out_dir,vlabel)
            zfile.create()

