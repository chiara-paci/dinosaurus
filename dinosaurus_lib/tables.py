class Cell(object):
    def __init__(self,txt,rowspan=1,colspan=1,th=False,style=""):
        self.rowspan=rowspan
        self.colspan=colspan
        self.txt=txt
        self.th=th
        self.style=style

    def __str__(self): 
        if self.th:
            S='<th'
        else:
            S='<td'
        if self.rowspan>1:
            S+=' rowspan="'+str(self.rowspan)+'"'
        if self.colspan>1:
            S+=' colspan="'+str(self.colspan)+'"'
        if self.style:
            S+=' class="'+self.style+'"'
        S+='>'+str(self.txt)+'</'
        if self.th:
            S+='th>'
        else:
            S+='td>'
        return S

class Row(list):
    def __init__(self,data=[]):
        list.__init__(self,data)
        self.style=""
        self.dom_id=""

    def tag(self):
        x="<tr"
        if self.style:
            x+=' class="'+self.style+'"'
        if self.dom_id:
            x+=' id="'+self.dom_id+'"'
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
        self._data[r][c].txt=txt

    def set_span(self,r,c,rowspan=1,colspan=1):
        self._data[r][c].rowspan=rowspan
        self._data[r][c].colspan=colspan
        
    def set_style(self,r,c,th=False,style=""):
        self._data[r][c].th=th
        self._data[r][c].style=style

    def set_row_style(self,r,style=""):
        self._data[r].style=style

    def set_row_id(self,r,row_id=""):
        self._data[r].dom_id=row_id

    def __str__(self):
        S=""
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
                S+=str(self._data[r][c])
            S+='</tr>\n'
                

        if self.tbody:
            S+='</'+self.tbody+'>'
        if self.table:
            S+='</table>\n'
        return S
