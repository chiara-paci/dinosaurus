from dinosaurus_lib.functions import *

class Cell(object):
    def __init__(self,txt,rowspan=1,colspan=1,th=False,style="",back_color="",data=[]):
        self.rowspan=rowspan
        self.colspan=colspan
        self.txt=unicode_convert(txt)
        self.th=th
        self.style=style
        self.cell_type=unicode(self.__class__.__name__).lower()
        self.back_color=back_color
        self.data=data

    def __str__(self): 
        return self._S(self.txt)

    def __unicode__(self): 
        return self._S(self.txt)

    def _S(self,txt):
        if self.th:
            S=u'<th'
        else:
            S=u'<td'
        if self.rowspan>1:
            S+=u' rowspan="'+unicode(self.rowspan)+'"'
        if self.colspan>1:
            S+=u' colspan="'+unicode(self.colspan)+'"'
        if self.style:
            S+=' class="'+self.style+'"'
        if self.back_color:
            S+=' style="background:'+self.back_color+'"'
        if self.data:
            for k,v in self.data:
                S+=' data-'+unicode_convert(k)+'="'+unicode_convert(v)+'"'
        S+='>'+unicode_convert(txt)+'</'
        if self.th:
            S+='th>'
        else:
            S+='td>'
        return S

class CellEmpty(Cell):
    def __init__(self):
        Cell.__init__(self,"",rowspan=0,colspan=0)

    def __str__(self): return ""

    def __unicode__(self): return u""

class CellOpen(Cell):
    def __init__(self,name,base_id,row_id,txt,rowspan=1,colspan=1,th=False,style=""):
        Cell.__init__(self,txt,rowspan=rowspan,colspan=colspan,th=th,style=style)
        self.name=unicode_convert(name)
        self.base_id=base_id
        self.row_id=row_id

    def __str__(self):
        open_label=u'<a name="'+self.name+u'"></a>'
        for lab,other,icon in [ (u"open",u"close",u"right"),(u"close",u"open",u"down") ]:
            open_label+=u'<a href="" class="'+lab+u'" '
            open_label+=u' id="'+lab+self.base_id+u'"'
            open_label+=u' data-'+other+u'="#'+other+self.base_id+u'"'
            open_label+=u' data-target="#'+self.row_id+u'">'
            open_label+=u'&nbsp;<i class="fa fa-caret-'+icon+u'"></i>&nbsp;</a>'
        return self._S(open_label+self.txt)

class CellSequence(list):
    def __init__(self,L):
        list.__init__(self)
        map(lambda x: self.append(Cell("")),range(0,L))

    def set_style(self,style,*args):
        if not args: args=range(0,len(self))
        for ind in args:
            self[ind].style=style

    def set_all_colspan(self):
        self[0].colspan=len(self)
        for c in range(1,len(self)):
            self[c]=CellEmpty()

    def set_back_color(self,color,*args):
        if not args: args=range(0,len(self))
        for ind in args:
            self[ind].back_color=color

    def set_val(self,val,*args):
        if not args: args=range(0,len(self))
        for ind in args:
            self[ind].txt=unicode_convert(val)

    def add_val(self,val,*args):
        if not args: args=range(0,len(self))
        for ind in args:
            self[ind].txt+=unicode_convert(val)

    def __str__(self):
        S=u"".join(map(unicode_convert,self))
        return S

    def __unicode__(self):
        S=u"".join(map(unicode_convert,self))
        return S

    def __add__(self,other):
        L=len(self)+len(other)
        ret=CellSequence(L)
        for n in range(0,len(self)):
            ret[n]=self[n]
        L=len(self)
        for n in range(0,len(other)):
            ret[n+L]=other[n]
        return ret

class Row(list):
    def __init__(self,cells=[]):
        list.__init__(self,cells)
        self.style=""
        self.dom_id=""
        self.data=[]

    def tag(self):
        x="<tr"
        if self.style:
            x+=' class="'+self.style+'"'
        if self.dom_id:
            x+=' id="'+self.dom_id+'"'
        if self.data:
            for k,v in self.data:
                x+=' data-'+k+'="'+unicode_convert(v)+'"'
        x+='>'
        return x

class Table(object):
    def __init__(self,num_rows,num_cols,table=False,tbody="tbody",style=""):
        self.num_rows=num_rows
        self.num_cols=num_cols
        self.table=table
        self.tbody=tbody
        self.style=style
        
        self._data=map(lambda r: Row(map(lambda c: Cell(""),range(0,self.num_cols))),
                       range(0,self.num_rows))

    def set_all_th(self):
        for r in range(0,self.num_rows):
            for c in range(0,self.num_cols):
                self._data[r][c].th=True

    def set_val(self,r,c,txt):
        if isinstance(self._data[r][c],CellEmpty):
            self._data[r][c]=Cell("")
        self._data[r][c].txt=unicode_convert(txt)

    def set_open(self,r,c,name,base_id,row_id,txt):
        if isinstance(self._data[r][c],CellOpen): return
        self._data[r][c]=CellOpen(name,base_id,row_id,txt)
        

    def set_span(self,r,c,rowspan=1,colspan=1):
        self._data[r][c].rowspan=rowspan
        self._data[r][c].colspan=colspan

        for qr in range(r,self.num_rows):
            for qc in range(c,self.num_cols):
                if (r==qr) and (c==qc): continue
                if (qr<r+rowspan) and (qc<c+colspan):
                    self._data[qr][qc]=CellEmpty()
                    continue
                if isinstance(self._data[r][c],CellEmpty):
                    self._data[qr][qc]=Cell("")
        
    def set_style(self,r,c,th=False,style=""):
        self._data[r][c].th=th
        self._data[r][c].style=style

    # data=[ (k,v)..]
    def set_data(self,r,c,data):
        for k,v in data:
            self._data[r][c].data.append((k,v))
    
    def set_row(self,r,cell_seq):
        for c in range(0,min(len(cell_seq),self.num_cols)):
            self._data[r][c]=cell_seq[c]

    # data=[ (k,v)..]
    def set_row_data(self,r,data):
        for k,v in data:
            self._data[r].data.append((k,v))

    def set_row_style(self,r,style=""):
        self._data[r].style=style

    def set_row_id(self,r,row_id=""):
        self._data[r].dom_id=row_id

    def __str__(self): return self.__unicode__()

    def __unicode__(self):
        S=u""
        if self.table:
            S+='<table'
            if self.style:
                S+=' class="'+self.style+'"'
            S+='>\n'
            if self.tbody:
                S+='<'+self.tbody+'>\n'
        elif self.tbody:
            S+='<'+self.tbody
            if self.style:
                S+=' class="'+self.style+'"'
            S+='>\n'

        empties=[]
        for r in range(0,self.num_rows):
            for c in range(0,self.num_cols):
                if (self._data[r][c].colspan > 1) or (self._data[r][c].rowspan > 1):
                    for qr in range(r,r+self._data[r][c].rowspan):
                        for qc in range(c,c+self._data[r][c].colspan):
                            if (r==qr) and (c==qc): continue
                            empties.append( (qr,qc) )

        r=0
        for r in range(0,self.num_rows):
            S+=self._data[r].tag()
            for c in range(0,self.num_cols):
                if (r,c) in empties: continue
                S+=unicode_convert(self._data[r][c])
            S+='</tr>\n'
                

        if self.tbody:
            S+='</'+self.tbody+'>'
        if self.table:
            S+='</table>\n'
        return S
