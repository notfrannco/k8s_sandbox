# kubernetes en HA

# Overview del diagrama de k8s en HA
![kube-vip-2](https://github.com/notfrannco/k8s_sandbox/assets/19764680/6895115f-11ac-499f-ac4c-afbd5156bfb7)




## Prerequisites
* IP disponible para ser utilizada como virutal IP por el kuve-vip.
* 3+ nodos de kubernete para control plane

## Configure Ansible Inventory
Modificar el inventorio $HOME/inventory/dev/hosts de acuerdo a la necesidad.<br />
Ejemplo inventory<br />
**hosts.yml**
```
[master]
k8s-control-plane ansible_host=192.168.100.72

[workers]
k8s-worker-1 ansible_host=192.168.100.74
k8s-worker-2 ansible_host=192.168.100.75
k8s-worker-2 ansible_host=192.168.100.76

[control_planes]
k8s-control-plane-2 ansible_host=192.168.100.71
k8s-control-plane-3 ansible_host=192.168.100.73
```
**OBS**: Los nombres en el inventario de ansible son solo alias de referencia para ansible, los nombres que se reflejaran en el kubernetes son por defecto los nombres de hostname de cada nodo.
Excluyendo el nombre "***k8s-control-plane***" del grupo "***masters***", todos los otros nombres del inventario pueden ser cambiados a cualquier nomenclatura que se desea






