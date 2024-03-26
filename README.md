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




