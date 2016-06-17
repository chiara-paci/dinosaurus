class Labeler(object):
    def __init__(self,name,num_header_rows,num_cols):
        self.name=name
        self.num_cols=num_cols
        self.num_header_rows=num_header_rows

    def __str__(self): return self.name+" ("+str(self.num_header_rows)+","+str(self.num_cols)+")"

    def set_header(self,tab,col_start,num_rows):
        pass

    def set_data(self,tab,row,row_start,col_start,num_rows):
        pass

    def get_style(self,row):
        return ""

class ListLabeler(Labeler):
    def __init__(self,name,lists,data_callable,no_label="",no_style_row="",no_style_cell=""):
        """ lists = [ (label,style_row,style_cell,key_list) ]
            key = data_callable(row)
        """
        Labeler.__init__(self,name,1,1)
        self.lists=lists
        self.no_label=no_label
        self.no_style_row=no_style_row
        self.no_style_cell=no_style_cell
        self.data_callable=data_callable

    def set_header(self,tab,col_start,num_rows):
        tab.set_span(0,col_start,rowspan=num_rows)
        tab.set_val(0,col_start,self.name)

    def get_style_row(self,row):
        key=self.data_callable(row)
        for label,style_row,style_cell,key_list in self.lists:
            if key in key_list:
                return style_row
        return self.no_style_row

    def get_style_cell(self,row):
        key=self.data_callable(row)
        for label,style_row,style_cell,key_list in self.lists:
            if key in key_list:
                return style_cell
        return self.no_style_cell

    def set_data(self,tab,row,row_start,col_start,num_rows):
        key=self.data_callable(row)
        tab.set_span(row_start,col_start,rowspan=num_rows)
        style=self.get_style_cell(row)
        if style:
            tab.set_style(row_start,col_start,style=style)
        for label,style_row,style_cell,key_list in self.lists:
            if key in key_list:
                tab.set_val(row_start,col_start,label)
                return 
        tab.set_val(row_start,col_start,self.no_label)


class DictLabeler(Labeler):
    def __init__(self,name,key_dict,data_callable,no_label="",no_style_row="",no_style_cell=""):
        """ key_dict = { key: (label,style_row,style_cell), ... }
            key = data_callable(row)
        """
        Labeler.__init__(self,name,1,1)
        self.key_dict=key_dict
        self.no_label=no_label
        self.no_style_row=no_style_row
        self.no_style_cell=no_style_cell
        self.data_callable=data_callable

    def set_header(self,tab,col_start,num_rows):
        tab.set_span(0,col_start,rowspan=num_rows)
        tab.set_val(0,col_start,self.name)

    def get_style_row(self,row):
        key=self.data_callable(row)
        if self.key_dict.has_key(key):
            return self.key_dict[key][1]
        return self.no_style_row

    def get_style_cell(self,row):
        key=self.data_callable(row)
        if self.key_dict.has_key(key):
            return self.key_dict[key][2]
        return self.no_style_cell

    def set_data(self,tab,row,row_start,col_start,num_rows):
        key=self.data_callable(row)
        style=self.get_style_cell(row)
        if style:
            tab.set_style(row_start,col_start,style=style)
        tab.set_span(row_start,col_start,rowspan=num_rows)
        if self.key_dict.has_key(key):
            tab.set_val(row_start,col_start,self.key_dict[key][0])
            return 
        tab.set_val(row_start,col_start,self.no_label)


class DictMultipleLabeler(Labeler):
    def __init__(self,name,titles,key_dict,data_callable,no_label="",no_style_row="",no_style_cell=""):
        """ titles = [title,...]
            key_dict = { key: ([label,...],style_row,style_cell), ... }
            key = data_callable(row)
        """
        Labeler.__init__(self,name,2,len(titles))
        self.titles=titles
        self.key_dict=key_dict
        self.no_label=no_label
        self.no_style_row=no_style_row
        self.no_style_cell=no_style_cell
        self.data_callable=data_callable

    def set_header(self,tab,col_start,num_rows):
        tab.set_span(0,col_start,rowspan=num_rows-1,colspan=self.num_cols)
        tab.set_val(0,col_start,self.name)
        c=col_start
        for title in self.titles:
            tab.set_val(num_rows-1,c,title)
            c+=1

    def get_style_row(self,row):
        key=self.data_callable(row)
        if self.key_dict.has_key(key):
            return self.key_dict[key][1]
        return self.no_style_row

    def get_style_cell(self,row):
        key=self.data_callable(row)
        if self.key_dict.has_key(key):
            return self.key_dict[key][2]
        return self.no_style_cell

    def set_data(self,tab,row,row_start,col_start,num_rows):
        key=self.data_callable(row)
        style=self.get_style_cell(row)

        if not self.key_dict.has_key(key):
            if style:
                tab.set_style(row_start,c+col_start,style=style)
            tab.set_span(row_start,col_start,rowspan=num_rows,colspan=self.num_cols)
            tab.set_val(row_start,col_start,self.no_label)
            return

        c=col_start
        for val in self.key_dict[key][0]:
            tab.set_val(row_start,c,val)
            if style:
                tab.set_style(row_start,c,style=style)
            tab.set_span(row_start,c,rowspan=num_rows)
            c+=1

        

