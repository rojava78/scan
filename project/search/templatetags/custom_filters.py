from django import template

register = template.Library()

@register.filter
def custom_filter(dict_obj, key):
    # Logic for your filter
    return dict_obj.get(key)
