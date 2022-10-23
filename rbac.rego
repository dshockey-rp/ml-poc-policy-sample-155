# Role-based Access Control (RBAC)
# --------------------------------
#
# For more information see:
#
#	* Rego comparison to other systems: https://www.openpolicyagent.org/docs/latest/comparison-to-other-systems/
#	* Rego Iteration: https://www.openpolicyagent.org/docs/latest/#iteration

package app.rbac

# import data.utils

# By default, deny requests
default allow = false
default role_includes_admin = false

# Allow the action if the user is granted permission to perform the action.
allow {
  # Find permissions for the user.
  some permission
  role_is_granted[permission]

  # Check if the permission permits the action.
  input.action == permission.action
  input.type == permission.type
}

allow {
  role_includes_admin  
}

# user_is_admin is true if...
role_includes_admin {
  input.roles[_] == "admin"
}

# user_is_granted is a set of permissions for the user identified in the request.
# The `permission` will be contained if the set `user_is_granted` for every...
role_is_granted[permission] {
  permission := data.role_permissions[input.roles[_]][_]
}

