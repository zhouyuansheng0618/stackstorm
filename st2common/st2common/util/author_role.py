
default_role = ['system_admin','admin','observer',None]

def judge(role):

    return True if role in default_role else False