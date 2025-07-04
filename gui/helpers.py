def update_combobox(combo, keys_list):
    keynames = [f"{k['name']} ({k['date']})" for k in keys_list]
    combo['values'] = keynames

def fill_widget(widget, value):
    widget.delete('1.0', 'end')
    widget.insert('1.0', value)