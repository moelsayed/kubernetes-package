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
    host_uuid=$(curl -s http://rancher-metadata/2015-12-19/self/host/uuid)
    host_name=$(curl -s http://rancher-metadata/2015-12-19/self/host/hostname)
    # hosts created using rancher-machine create their own security group.
    host_security_group="${host_name}-firewall"
    rancher_server=${CATTLE_URL%/v1}
    curl -s -u $CATTLE_ACCESS_KEY:$CATTLE_SECRET_KEY $rancher_server/v2-beta/hosts?uuid=$host_uuid | jq .data[0].azureConfig |
    jq ". |= .+ {\"tenantId\": \"${AZURE_TENANT_ID}\", \"securityGroupName\": \"${host_security_group}\"}" |
    jq 'del(.size, .dns, .image, .dockerPort, .openPort, .noPublicIp, .usePrivateIp, .customData)' |
    jq 'del(.privateIpAddress, .sshUser, .storageType, .subnetPrefix, .staticPublicIp, .availabilitySet)' |
    sed \
      -e "s|environment|cloud|g" \
      -e "s|clientId|aadClientId|g" \
      -e "s|clientSecret|aadClientSecret|g" \
      -e "s|\"vnet\"|\"vnetName\"|g" \
      -e "s|\"subnet\"|\"subnetName\"|g" \
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
