# k8s sandbox


Playbook de ansible que instala un cluster de kubernetes 1.29 sobre Ubuntu 22.04 LTS.

## Prerequisites
* Servidor Bastion para el ansible.
* Creacion de un usuario admin ansible para administrar los servidores

## Diagrama de flujo (working progress )
![diagrama_inicial](https://github.com/notfrannco/k8s_sandbox/assets/19764680/657a918d-28b9-4d99-8e10-7796b0748773)


## Create Ansible Admin user
Utilizar el playbook add_ansible_user.yml, y especificar el usuario admin(root o usuario con sudo) para la configuracion inicial <br /><br />
 `$ ansible-playbook utils/add_ansible_user.yml -u <admin_user> -b -k`

Prueba de conexion a todos los servers <br /><br />
`$ ansible all -m ping`


## Hardening server (CIS compliance)
Correr el role de hardening de servidores, esto puede tardar mucho y reiniciara las vms para que aplique ciertas configuraciones <br /><br />
 `$ ansible-playbook hardening.yml`

 Se puede especificar un host especifico, multiple hosts o grupo de hosts... validar la configuracion de inventory <br /><br />
 `$ ansible-playbook hardening.yml -l k8s_master`          <t/># correr solo en el servidor k8s_master<br />
 `$ ansible-playbook hardening.yml -l k8s_master:worker-1` # correr solo en el servidor k8s_master y worker-1<br />
 `$ ansible-playbook hardening.yml -l grupo_workers`       # correr en todos los servers listados en el grupo "grupo_workers"1<br />

# Config k8s Cluster
## Install Dependencies (all nodes)
Instalar las dependencias necesarias en todos los nodos.  <br />

`$ ansible-playbook k8s_dependecies.yml`<br />

Si se desea correr en nodos especificos. <br />

 `$ ansible-playbook k8s_dependecies.yml -l k8s_master`          <t/># correr solo en el servidor k8s_master<br />
 `$ ansible-playbook k8s_dependecies.yml -l k8s_master:worker-1` # correr solo en el servidor k8s_master y worker-1<br />
 `$ ansible-playbook k8s_dependecies.yml -l grupo_workers`       # correr en todos los servers listados en el grupo "grupo_workers"1<br />


## Configure Control Plane
Verificar inicialmente el inventario de ansible y listar el control plane principal en el grupo "master" y los workers en el grupo workers.<br />
Ejemplo inventory<br />
**hosts.yml**
```
[master]
k8s-control-plane ansible_host=10.0.0.1

[workers]
k8s-worker-1 ansible_host=10.0.0.2
k8s-worker-2 ansible_host=10.0.0.3
```
Configurar el control plane <br /><br />
 `$ ansible-playbook k8s_master.yml`

Conectarse al servidor y verificar el estado
```
ansible@k8s-control-plane:~$ kubectl get nodes
NAME                STATUS   ROLES           AGE     VERSION
k8s-control-plane   Ready    control-plane   8m27s   v1.29.3

```

## Configure Workers
 `$ ansible-playbook k8s_worker.yml`

# Add new Nodes
## Add new Control plane
Para agregar mas control plane se requiere editar el inventario de hosts y listar los nuevos nodos en el grupo "control-planes" como se observa en el ejemplo de inventario.<br />
```
[master]
k8s-control-plane ansible_host=192.168.100.68

[workers]
k8s-worker-1 ansible_host=192.168.100.69
k8s-worker-2 ansible_host=192.168.100.70

[control-planes]
k8s-control-plane-2
k8s-control-plane-3

```
El grupo "master" del inventario deberia apuntar a tu control plane principal al cual el ansible se conectara para consultar la API y realizar de mas configuraciones, este control plane "principal" puede ser cualquier control plane.<br /><br />
Para agregar nuevos control plane ejecutamos el siguiente playbook.<br />
 `$ ansible-playbook k8s_add_master.yml`



## Add new worker
Para agregar un nuevo worker se puede volver a ejecutar el playbook "k8s_worker.yml" y especificar el nuevo workers o listar los nuevos si son multiples nodos.<br />
`$ ansible-playbook k8s_worker.yml -l worker-3` # ejecutar solo en el nodo nuevo worker-3<br />
`$ ansible-playbook k8s_worker.yml -l worker-3:worker-4` # ejecutar solo en el nodo nuevo worker-3 y worker-4<br />


# RBAC
## Configure roles for specfic users
agrega el role "basic-user" al usuario "jose" en el namespace "default"<br />
 `$ ansible-playbook  k8s_rbac/k8s_rbac_add_role.yml -e user=jose -e ns=default -e role=basic-user` 

 <br />Se puede especificar varios roles separados por  ","  <br />
 `$ ansible-playbook  k8s_rbac/k8s_rbac_add_role.yml -e user=jose -e ns=default -e role=basic-user,admin,cluster-reader` 

 <br />**Add new cluster admin user** <br />
 `$ ansible-playbook  k8s_rbac/k8s_rbac_add_role.yml -e user=jose -e role=cluster-admin` 

  <br />**Delete** user role<br />
 `$ ansible-playbook  k8s_rbac/k8s_rbac_delete_user_role.yml -e user=jose -e ns=default -e role=basic-user,admin,cluster-reader`

   <br />**Delete** user role que es cluster-admin<br />
 `$ ansible-playbook  k8s_rbac/k8s_rbac_delete_user_role.yml -e user=jose -e role=cluster-admin`

## Configure default .kube/config for specific user (pki)
Configuracion default de pki, se deben especificar el usuario y los dias de validez <br />
 `$ ansible-playbook k8s_rbac/k8s_create_credential.yml -e user=jose -e days=30` 


# MetalLB
## Configure MetalLB
agrega el rango de IPs en "files/metalLB-values.yml"<br />

 ```
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: first-pool
  namespace: metallb-system
spec:
  addresses:
  - 192.168.100.77-192.168.100.83  **# set IP range**

```

  <br />Install MetalLB <br />
 `$ ansible-playbook install_metalLB.yml `


# Longhorn
## Configure longhorn
Configuracion de prerequisitos y dependencias<br />
 `$ ansible-playbook utils/setup_req_longhorn.yml` 

 Configuracion de labels para los nodos a ser utilizados por longhorn, configurar acorde a necesidad<br />
 `$ ansible-playbook utils/k8s_label_nodes.yml` 

 Install longhorn <br />
 `$ ansible-playbook install_longhorn.yml` 



 <br /> <br />

# Kubernetes en HA con kube-vip
Validar la documentacion en ***k8s_ha/README.md*** <br />

Primero instalamos las dependencias necesarias, en todos los nodos<br />
 `$ ansible-playbook k8s_dependecies.yml` 

Configuramos el control plane inicial (kubeadm init)<br />
 `$ ansible-playbook k8s_ha/k8s_ha_master.yml` 

Configuramos el resto de control planes <br />
 `$ ansible-playbook k8s_ha/k8s_ha_add_master.yml` 

Por ultimo configuramos los workers <br />
 `$ ansible-playbook k8s_ha/k8s_ha_worker.yml` 
