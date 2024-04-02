#!/usr/bin/env bash

all_args=("$@")
user="$1"
namespace="$2"
roles=("${all_args[@]:2}")
list_roles=(${roles//,/ }) # split argument that uses a ,


# debug, print vars
echo "user: $user "
echo "namespace: $namespace"
echo "roles: ${list_roles[@]}"
echo "roles var: $roles"
echo "-----------------------------------------------------------------------------"

#current_roles=$(kubectl get role -n $2 | awk '(NR>1)' | awk '{ print $1 }' )

if [[ $# == 2 ]]; then # cluster roles cluster admin
    kubectl get clusterrolebinding $2 -o yaml > lab1-$2-binding.yaml   # temp config yaml file
    yq -i 'del(.subjects[] | select(.name == "'$user'"))' lab1-$2-binding.yaml      # the 2 args is the role en cluster-admin
    kubectl apply -f lab1-$2-binding.yaml                                        # apply changes
    #rm lab1-$role-binding.yaml 
else
  # validar si el rolebinding existe, crear si no
  role_binding_state=$(kubectl get rolebinding/$role -n $namespace 2> /dev/null )
  if [[ -n $role_binding_state ]]; then  # if the role exists
      echo "the role exists"
      kubectl get rolebinding $role -n $namespace -o yaml > lab1-$role-binding.yaml   # temp config yaml file
      yq -i 'del(.subjects[] | select(.name == "'$user'"))' lab1-$role-binding.yaml      # delete the user 
      kubectl apply -f lab1-$role-binding.yaml                                        # apply changes
      rm lab1-$role-binding.yaml                                                      # delete temp config file
  fi

fi
