import copy
import datetime

from dinosaurus_lib.dnsdatabase import Zone,View,Record,DnsDatabase
from dinosaurus_lib.config import *

class FilterCascade(object):
    def __init__(self,*args):
        self.callables=[]
        for f in args:
            self.callables.append(f)

    def filter_db(self,db):
        for f in self.callables:
            db=f(db)
        return db

    def filter_zone(self,zone):
        for f in self.callables:
            zone=f(zone)
        return zone

    def filter_record(self,record):
        for f in self.callables:
            record=f(record)
        return record

    def __call__(self,old_db,new_name):
        print "Copy"
        new_db=copy.deepcopy(old_db)
        new_db.name=new_name

        print "Apply filters on db"
        new_db=self.filter_db(new_db)

        print "Apply filters on zones"
        new_db.zones=map(self.filter_zone,new_db.zones)
        new_db.zones_ip6=map(self.filter_zone,new_db.zones_ip6)

        print "Apply filters on records"
        for zone in new_db.zones+new_db.zones_ip6:
            zone.rows=map(self.filter_record,zone.rows)
            zone.def_rows=map(self.filter_record,zone.def_rows)

        print "Calculate"
        new_db.calculate()
        return new_db
    

def dummy_filter(old_db):
    print "Dummy filter"
    return old_db

class BaseFunction(object):
    def __init__(self):
        self.map_callables= [ (Zone,self.process_zone),
                              (Record,self.process_record),
                              (DnsDatabase,self.process_db) ]
                              

    def process_zone(self,zone): return zone
    def process_record(self,record): return record
    def process_db(self,dns_db): return dns_db

    def __call__(self,obj):
        for cl,func in self.map_callables:
            if isinstance(obj,cl):
                return func(obj)
        return NotImplemented

class NormalizeSOA(BaseFunction):
    def __init__(self,primary_master,email_admin):
        BaseFunction.__init__(self)
        self.primary_master=primary_master
        self.email_admin=email_admin
        t=datetime.datetime.today()
        self.serial_number="%4.4d%2.2d%2.2d%2.2d" % (t.year,t.month,t.day,00)

    def process_zone(self,zone):
        collect_data={}
        collect_data["refresh"]=set()
        collect_data["retry"]=set()
        collect_data["expiry"]=set()
        collect_data["nx_ttl"]=set()
        collect_data["ttl"]=set()

        for view,data,ttl in zone.soa_record.record.data:
            collect_data["refresh"].add(data[3])
            collect_data["retry"].add(data[4])
            collect_data["expiry"].add(data[5]) 
            collect_data["nx_ttl"].add(data[6])
            collect_data["ttl"].add(ttl)

        for k in collect_data.keys():
            collect_data[k]=filter(lambda x: x not in ["_",""],list(collect_data[k]))

        new_data=map(lambda x: "",range(0,7))
        new_data[0]=self.primary_master            
        new_data[1]=self.email_admin            
        new_data[2]=self.serial_number
        new_data[3]=max_or_default(collect_data["refresh"],DEFAULTS["refresh"])
        new_data[4]=max_or_default(collect_data["retry"],DEFAULTS["retry"])
        new_data[5]=max_or_default(collect_data["expiry"],DEFAULTS["expiry"])
        new_data[6]=max_or_default(collect_data["nx_ttl"],DEFAULTS["nx_ttl"])

        new_ttl=max_or_default(collect_data["ttl"],[""])
        if not new_ttl:
            new_ttl=max_or_default(collect_data["nx_ttl"],DEFAULTS["ttl"])

        new_record_data=[]
        for view,data,ttl in zone.soa_record.record.data:
            new_record_data.append( (view,new_data,new_ttl) )

        zone.soa_record.record.data=new_record_data
        return zone
        # zone.soa_record.record.data=new_data

class MapViews(BaseFunction):
    def __init__(self,map_views):
        BaseFunction.__init__(self)
        views={}
        self.map_views={}
        ind=0
        for old_view_name,new_view_name in map_views:
            if not views.has_key(new_view_name):
                views[new_view_name]=View(ind,new_view_name)
            self.map_views[old_view_name]=views[new_view_name]
            ind+=1

    def process_db(self,db):
        new_views=set()
        for old_view in db.views:
            new_views.add(self.map_views[old_view.name])
        new_views=list(new_views)
        new_views.sort()
        db.views=new_views
        return db

    def process_record(self,record):
        new_record_data=[]
        for old_view,data,ttl in record.data:
            new_record_data.append( (self.map_views[old_view.name],data,ttl) )
        record.data=new_record_data
        return record
        

### Creare un filtro che fa questo

    # self.view_map_to_new={
    #     "any":     self.view_files["public_internet"],
    #     "guest":   self.view_files["public_guest"],
    #     "extra":   self.view_files["public_extranet"],
    #     "windows": self.view_files["private_intranet"],
    #     "intra":   self.view_files["private_intranet"],
    # }
