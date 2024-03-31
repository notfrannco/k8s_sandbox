# Kubernetes RBAC Overview
## Resources Scope

![Untitled Diagram-role-scope](https://github.com/notfrannco/k8s_sandbox/assets/19764680/3d04842a-fab5-4062-bc41-c658b2a865b6)
<br />
<br />
<br />
![Untitled Diagram-roles-permissions](https://github.com/notfrannco/k8s_sandbox/assets/19764680/15fc04d9-bdef-4330-9c6d-8fcb18c4668c)







## Default Roles
| Role | Scope | Description |
| --------| ------- |--------|
| **cluster-admin**     |   Cluster       | Usuario admin del cluster de k8s
|  **admin**    | namespace      | Usuario admin del proyecto, puede modificar todo dentro del namespace especificado
|  **basic-user**   |     namespace       | Similar al role "admin", pero no puede modificar "networkpolicies" y "quotas"
|  **cluster-reader**      |   cluster     | Usuario con permisos de lecturas a resources de scope non-namespace
|  **cluster-status**     |   cluster      | Usuario con permisos de lectura a nodes, pv, csr, ingressclass y storageclass


<br /> Inicialmente se utilizaran los roles definidos anteriormente y se modificaran de acuerdo a necesidad en cada proyecto.
<br /> El siguiente grafico ilustra el diagrama general del scope de los permisos.

![Untitled Diagram-rbac_namespace](https://github.com/notfrannco/k8s_sandbox/assets/19764680/7c721049-e396-40a1-8cd4-a16b22f7da1f)




