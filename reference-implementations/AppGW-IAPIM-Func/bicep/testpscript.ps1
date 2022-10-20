$LOCATION = "canadacentral"

# delete a deployment
az deployment sub  delete  --name testasedeployment

# deploy the bicep file directly

az deployment sub  create --name testasedeployment   --template-file main.bicep   --parameters parameters.json --location $LOCATION -o json
