# -*- coding: utf-8 -*-

import os.path
import pickle

import dinosaurus_lib.config as dns_config
import dinosaurus_lib.output_views as dns_output_views
import dinosaurus_lib.dnsdatabase as dns_database

class Elaboration(object):
    def __init__(self,out_dir,label,title,view_params):
        self.out_dir=out_dir
        self.label=label
        self.title=title
        self.view_params=view_params
        self.dir_conf=out_dir+"/"+label+"_conf"
        self.dir_html=out_dir+"/"+label+"_html"
        self.dir_local_html=out_dir+"/"+label+"_local_html"
        self.context="/"+label+"_html"
        self.pickle_fname=out_dir+"/db_"+label+".pickle"
        self.db=None
        self.dir_local_static=out_dir+"/static_local"
        self.dir_static=out_dir+"/static"
        self.static_root="/static"

        self.menus_local={ "single_db": [], 
                           "main": [ ("file:///"+out_dir+"/index_local.html","Home") ] }
        self.menus={ "single_db": [],
                     "main": [ ("/","Home") ] }
        
        self.theme="dinosaurus"

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

    def html_local_view(self,*args,**kwargs):
        self.menus_local["main"].append( ("file:///"+self.dir_local_html+"/index.html",self.db.name) )

        static_root="file://"+dns_config.THEMES_DIR+"/"+self.theme+"/static"

        context_manager=dns_output_views.ContextManager(self.dir_local_html,
                                                        "file:///"+self.dir_local_html,
                                                        static_root,
                                                        self.theme,
                                                        self.menus_local,self.db.name)

        oview=dns_output_views.HtmlView(self.db,context_manager,*args,**kwargs)
        oview.output()

    def html_view(self,*args,**kwargs):
        self.menus["main"].append( (self.context,self.db.name) )

        context_manager=dns_output_views.ContextManager(self.dir_html,self.context,
                                                        self.static_root,self.theme,
                                                        self.menus,self.db.name)

        oview=dns_output_views.HtmlView(self.db,context_manager,*args,**kwargs)
        oview.output()
        
    def conf_view(self,*args,**kwargs):
        oview=dns_output_views.ConfView(self.db,self.dir_conf,self.view_params)
        oview.output()
        
    def cmd_view(self,*args,**kwargs):
        #oview=dns_output_views.CmdView(self.dir_conf,self.view_params)
        #oview.output(self.db)
        pass


class ElaborationFile(Elaboration):
    def __init__(self,out_dir,label,title,view_params,fname):
        Elaboration.__init__(self,out_dir,label,title,view_params)
        self.fname=fname
    
    def build(self):
        self.db=dns_database.DnsDatabaseFile(self.fname,self.title)

class ElaborationFilter(Elaboration):
    def __init__(self,out_dir,label,title,view_params,current_db,dns_filter):
        Elaboration.__init__(self,out_dir,label,title,view_params)
        self.filter=dns_filter
        self.current_db=current_db

    def build(self):
        self.db=self.filter(self.current_db,self.title)

