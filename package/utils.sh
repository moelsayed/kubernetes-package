
AZURE_META_URL="http://169.254.169.254/metadata/instance/compute"
get_azure_config() {
  local az_resources_group=$(curl  -s -H Metadata:true "${AZURE_META_URL}/resourceGroupName?api-version=2017-08-01&format=text")
  local az_subscription_id=$(curl -s -H Metadata:true "${AZURE_META_URL}/subscriptionId?api-version=2017-08-01&format=text")
  local az_location=$(curl  -s -H Metadata:true "${AZURE_META_URL}/location?api-version=2017-08-01&format=text")
  local az_vm_name=$(curl -s -H Metadata:true "${AZURE_META_URL}/name?api-version=2017-08-01&format=text")

  # login to Azure
  az login --service-principal -u ${AZURE_CLIENT_ID} -p ${AZURE_CLIENT_SECRET} --tenant ${AZURE_TENANT_ID} 2>&1 > /dev/null

  local az_vm_nic=$(az vm nic list -g ${az_resources_group} --vm-name ${az_vm_name} | jq -r .[0].id | cut -d "/" -f 9)
  local az_subnet_name=$(az vm nic show -g ${az_resources_group} --vm-name ${az_vm_name} --nic ${az_vm_nic}| jq -r .ipConfigurations[0].subnet.id| cut -d"/" -f 11)
  local az_vnet_name=$(az vm nic show -g ${az_resources_group} --vm-name ${az_vm_name} --nic ${az_vm_nic}| jq -r .ipConfigurations[0].subnet.id| cut -d"/" -f 9)
  local az_security_group=$(az vm nic show -g ${az_resources_group} --vm-name ${az_vm_name} --nic ${az_vm_nic}| jq -r .networkSecurityGroup.id| cut -d"/" -f 9)

  az logout 2>&1 > /dev/null

  echo "aadClientId: ${AZURE_CLIENT_ID}"
  echo "aadClientSecret: ${AZURE_CLIENT_SECRET}"
  echo "tenantId: ${AZURE_TENANT_ID}"
  echo "subscriptionId: ${az_subscription_id}"
  echo "cloud: ${AZURE_CLOUD:-AzurePublicCloud}"
  echo "location: ${az_location}"
  echo "resourceGroup: ${az_resources_group}"
  echo "subnetName: ${az_subnet_name}"
  echo "vnetName: ${az_vnet_name}"
  echo "securityGroupName: ${az_security_group}"
}
