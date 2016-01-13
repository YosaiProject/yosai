
Authorization API Reference
def requires_permission(permission_s, logical_operator=all):
def requires_role(roleid_s, logical_operator=all):

def is_permitted(self, permission_s):
def is_permitted_collective(self, permission_s, logical_operator):
def check_permission(self, permission_s, logical_operator):

def has_role(self, roleid_s):
def has_role_collective(self, roleid_s, logical_operator):
def check_role(self, role_ids, logical_operator):

