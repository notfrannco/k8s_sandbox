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

if [[ $# == 2 ]]; then # cluster roles
   echo "only 2 args pass" >> script.log
   # if role is cluster admin
   if [[ $role == "cluster-admin" ]]; then # cluster admin role
      echo "cluster admin role" >> script.log
      kubectl get clusterrolebinding $role -o yaml > lab1-$role-binding.yaml # get temp yaml file
      yq -i 'with(.subjects; select(all_c(.name != "'$user'")) | . += {"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": "'$user'"} )' lab1-$role-binding.yaml &> /dev/null
      kubectl apply -f lab1-$role-binding.yaml
      rm lab1-$role-binding.yaml
   fi

else # namespace scope role
   echo "more than 2 args pass" >> script.log
   for role in ${list_roles[@]}
   do
   echo "-----------------------------------------------------------------------------"
     # validar que el role existe, crear si no
     if [ $role == "cluster-reader" ] || [ $role == "cluster-status" ]; then # cluster roles
        echo "validating if cluster role $role exists" >> script.log
        kubectl get clusterrole $role   &> /dev/null
        if [ $? -eq 1 ]; then
           echo "cluster role $role  dont exit, creating" >> script.log
           kubectl create -f ${role}.yaml 
        fi
     else # namespace scope role
        echo "validating if role $role exists" >> script.log
        kubectl get role $role -n $namespace  &> /dev/null
        if [ $? -eq 1 ]; then
           kubectl create -f ${role}.yaml
        fi
     fi
   
   
     # validar si el rolebinding existe, crear si no
     role_binding_state=$(kubectl get rolebinding/$role -n $namespace 2> /dev/null )
   
     if [[ -z $role_binding_state ]]; then 
         echo "rolebinding $role don't exist creating rolebinding $role"
         if [ $role == "cluster-reader" ] || [ $role == "cluster-status" ]; then # if cluster role
           kubectl create rolebinding $role --clusterrole=$role --user=$user -n $namespace
         else
           kubectl create rolebinding $role --role=$role --user=$user -n $namespace
         fi
     fi
   
     # validar que la lista de subjects del rolebinding no este vacia
     # puesto que la forma de insertar items con yq cambia dependiento si esta vacia o no
     kubectl get rolebinding $role -n $namespace -o yaml > lab1-$role-binding.yaml # temp config yaml file
     yq eval 'with(.subjects; select(all_c(.name != "'$user'")) | . += {"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": "'$user'"} )' lab1-$role-binding.yaml &> /dev/null
   
     if [ $? -eq 1 ]; then # add user in a empty list
       yq -i '.subjects += [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": "'$user'"}] ' lab1-$role-binding.yaml &> /dev/null
     else # add user to exsinting list
       yq -i 'with(.subjects; select(all_c(.name != "'$user'")) | . += {"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": "'$user'"} )' lab1-$role-binding.yaml &> /dev/null
     fi
   
     # aplly changes
     kubectl apply -f lab1-$role-binding.yaml
     # clean up
     rm lab1-$role-binding.yaml
     
   done
fi
