# iati-identity-to-crm-sync

## Develop Locally

### Run Identity Service

```
docker run -it -p 9443:9443 --name iatiwso2is wso2/wso2is:7.1.0
```

Log in as admin / admin

### Run CRM

See https://github.com/IATI/iati-registry-localdev

## Setup

### Identity server

In identity server, create new M2M application.
In "API Authorization", Give it access to "SCIM2 Users API" with "View User" and "List User" authorized scopes.

### CRM

Create a user for this.

Admin, "OAuth2 Clients and Tokens", "New Client Credentials Client":
* use user you just created
* set your own secret

## Run

Set environment variables as needed - see bottom of script for details.

```
python sync.py
```


## Docs links

* https://is.docs.wso2.com/en/latest/references/grant-types/#client-credentials-grant
* https://is.docs.wso2.com/en/latest/apis/scim2/scim2-users-rest-api/
* https://docs.suitecrm.com/developer/api/developer-setup-guide/json-api/#_create_a_module_record

