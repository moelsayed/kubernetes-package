#!/bin/bash
set -e -x

if [ "$1" == "kubelet" ]; then
    if [ -d /var/run/nscd ]; then
        mount --bind $(mktemp -d) /var/run/nscd
    fi
fi

while ! curl -s -f http://rancher-metadata/2015-12-19/stacks/Kubernetes/services/kubernetes/uuid; do
    echo Waiting for metadata
    sleep 1
done

/usr/bin/update-rancher-ssl

UUID=$(curl -s http://rancher-metadata/2015-12-19/stacks/Kubernetes/services/kubernetes/uuid)
ACTION=$(curl -s -u $CATTLE_ACCESS_KEY:$CATTLE_SECRET_KEY "$CATTLE_URL/services?uuid=$UUID" | jq -r '.data[0].actions.certificate')
KUBERNETES_URL=${KUBERNETES_URL:-https://kubernetes.kubernetes.rancher.internal:6443}

if [ -n "$ACTION" ]; then
    mkdir -p /etc/kubernetes/ssl
    cd /etc/kubernetes/ssl
    curl -s -u $CATTLE_ACCESS_KEY:$CATTLE_SECRET_KEY -X POST $ACTION > certs.zip
    unzip -o certs.zip
    cd $OLDPWD

    TOKEN=$(cat /etc/kubernetes/ssl/key.pem | sha256sum | awk '{print $1}')

    cat > /etc/kubernetes/ssl/kubeconfig << EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    api-version: v1
    certificate-authority: /etc/kubernetes/ssl/ca.pem
    server: "$KUBERNETES_URL"
  name: "Default"
contexts:
- context:
    cluster: "Default"
    user: "Default"
  name: "Default"
current-context: "Default"
users:
- name: "Default"
  user:
    token: "$TOKEN"
EOF
fi

cat > /etc/kubernetes/authconfig << EOF
clusters:
- name: rancher-kubernetes-auth
  cluster:
    server: http://rancher-kubernetes-auth

users:
- name: rancher-kubernetes

current-context: webhook
contexts:
- context:
    cluster: rancher-kubernetes-auth
    user: rancher-kubernetes
  name: webhook
EOF

# generate Azure cloud provider config
if echo ${@} | grep -q "cloud-provider=azure"; then
  if [ "$1" == "kubelet" ] || [ "$1" == "kube-apiserver" ] || [ "$1" == "kube-controller-manager" ]; then
    AZURE_META_URL="http://169.254.169.254/metadata/instance/compute"
    
    az_resources_group=$(curl  -s -H Metadata:true "${AZURE_META_URL}/resourceGroupName?api-version=2017-08-01&format=text")
    az_subscription_id=$(curl -s -H Metadata:true "${AZURE_META_URL}/subscriptionId?api-version=2017-08-01&format=text")
    az_location=$(curl  -s -H Metadata:true "${AZURE_META_URL}/az_location?api-version=2017-08-01&format=text")
    az_vm_name=$(curl -s -H Metadata:true "${AZURE_META_URL}/name?api-version=2017-08-01&format=text")
    
    # login to Azure 
    az login --service-principal -u ${AZURE_CLIENT_ID} -p ${AZURE_CLIENT_SECRET} --tenant ${AZURE_TENANT_ID}

    az_cloud=$(az account show| jq -r .environmentName)
    az_vm_nic=$(az vm nic list -g ${az_resources_group} --vm-name ${az_vm_name} | jq -r .[0].id | cut -d "/" -f 9)
    az_subnet_name=$(az vm nic show -g ${az_resources_group} --vm-name ${az_vm_name} --nic ${az_vm_nic}| jq -r .ipConfigurations[0].subnet.id| cut -d"/" -f 11)
    az_vnet_name=$(az vm nic show -g ${az_resources_group} --vm-name ${az_vm_name} --nic ${az_vm_nic}| jq -r .ipConfigurations[0].subnet.id| cut -d"/" -f 9)
    az_security_group=$(az vm nic show -g ${az_resources_group} --vm-name ${az_vm_name} --nic ${az_vm_nic}| jq -r .networkSecurityGroup.id| cut -d"/" -f 9)

    az logout
     
    echo -e \
      "aadClientId: ${AZURE_CLIENT_ID}\n" \
      "aadClientSecret: ${AZURE_CLIENT_SECRET}\n"\
      "cloud: ${az_cloud}\n"\
      "location: ${az_location}\n"\
      "resourceGroup: ${az_resources_group}\n"\
      "subnetName: ${az_subnet_name}\n"\
      "subscriptionId: ${az_subscription_id}\n"\
      "vnetName: ${az_vnet_name}\n"\
      "tenantId: ${AZURE_TENENT_ID}\n"\
      "securityGroupName: ${az_security_group}\n"\
      > /etc/kubernetes/cloud-provider-config 

   fi
fi


if [ "$1" == "kubelet" ]; then
    for i in $(DOCKER_API_VERSION=1.22 ./docker info 2>&1  | grep -i 'docker root dir' | cut -f2 -d:) /var/lib/docker /run /var/run; do
        for m in $(tac /proc/mounts | awk '{print $2}' | grep ^${i}/); do
            if [ "$m" != "/var/run/nscd" ] && [ "$m" != "/run/nscd" ]; then
                umount $m || true
            fi
        done
    done
    mount --rbind /host/dev /dev
    mount -o rw,remount /sys/fs/cgroup 2>/dev/null || true
    for i in /sys/fs/cgroup/*; do
        if [ -d $i ]; then
             mkdir -p $i/kubepods
        fi
    done
fi

FQDN=$(hostname --fqdn || hostname)

if [ "$1" == "kubelet" ]; then
    CGROUPDRIVER=$(docker info | grep -i 'cgroup driver' | awk '{print $3}')
    exec "$@" --cgroup-driver=$CGROUPDRIVER --hostname-override ${FQDN}
fi

if [ "$1" == "kube-proxy" ]; then
    exec "$@" --hostname-override ${FQDN}
fi

if [ "$1" == "kube-apiserver" ]; then
    export RANCHER_URL=${CATTLE_URL}
    export RANCHER_ACCESS_KEY=${CATTLE_ACCESS_KEY}
    export RANCHER_SECRET_KEY=${CATTLE_SECRET_KEY}

    LABEL=$(rancher inspect --type=service rancher-kubernetes-agent | jq '.launchConfig.labels."io.rancher.k8s.agent"')
    if [ "${LABEL}" = "null" ]; then
        rancher rm --type=service rancher-kubernetes-agent
    fi

    CONTAINERIP=$(curl -s http://rancher-metadata/2015-12-19/self/container/ips/0)
    exec "$@" "--advertise-address=$CONTAINERIP"
fi

exec "$@"
