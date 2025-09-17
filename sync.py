import base64
import logging
import os
import sys

import requests
import urllib3


class Sync:

    def __init__(
        self,
        identity_service_url: str,
        identity_service_allow_self_signed_https: bool,
        identity_service_client_id: str,
        identity_service_client_secret: str,
        crm_url: str,
        crm_client_id: str,
        crm_client_secret: str,
        identity_service_paging: int = 10,
        error_if_crm_contact_not_exist: bool = True,
    ):
        self._identity_service_url = identity_service_url
        self._identity_service_allow_self_signed_https = (
            identity_service_allow_self_signed_https
        )
        self._identity_service_client_id = identity_service_client_id
        self._identity_service_client_secret = identity_service_client_secret
        self._crm_url = crm_url
        self._crm_client_id = crm_client_id
        self._crm_client_secret = crm_client_secret
        self._identity_service_paging = identity_service_paging
        self._error_if_crm_contact_not_exist = error_if_crm_contact_not_exist
        self._identity_service_access_token = None
        self._crm_access_token = None
        self._identity_service_requests_params = {}
        if self._identity_service_allow_self_signed_https:
            self._identity_service_requests_params["verify"] = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._logger = logging.getLogger(__name__)

    def sync(self):
        # Get Identity Service Token
        self._get_identity_service_token()
        # Get CRM token
        self._get_crm_access_token()
        # Get list of users, with paging
        startIndex = 1
        while True:
            self._logger.info("Getting users from {}".format(startIndex))
            r = requests.get(
                self._identity_service_url
                + "/scim2/Users?count={}&startIndex={}".format(
                    self._identity_service_paging, startIndex
                ),
                headers={
                    "Authorization": "Bearer " + self._identity_service_access_token,
                    "accept": "application/scim+json",
                },
                **self._identity_service_requests_params
            )
            r.raise_for_status()
            users_raw_data = r.json().get("Resources", [])
            if not users_raw_data:
                break
            for user_raw_data in users_raw_data:
                self._process_user(user_raw_data)
            startIndex += self._identity_service_paging

    def _get_identity_service_token(self):
        r = requests.post(
            self._identity_service_url + "/oauth2/token",
            headers={
                "Authorization": "Basic "
                + base64.b64encode(
                    (
                        self._identity_service_client_id
                        + ":"
                        + self._identity_service_client_secret
                    ).encode()
                ).decode()
            },
            json={
                "grant_type": "client_credentials",
                "scope": "internal_user_mgt_list internal_user_mgt_view",
            },
            **self._identity_service_requests_params
        )
        r.raise_for_status()
        self._identity_service_access_token = r.json().get("access_token")

    def _get_crm_access_token(self):
        r = requests.post(
            self._crm_url + "/Api/index.php/access_token",
            json={
                "grant_type": "client_credentials",
                "client_id": self._crm_client_id,
                "client_secret": self._crm_client_secret,
            },
            headers={
                "Content-type": "application/vnd.api+json",
                "Accept": "application/vnd.api+json",
            },
        )
        r.raise_for_status()
        self._crm_access_token = r.json().get("access_token")

    def _process_user(self, user_raw_data):
        self._logger.info(
            "User {}".format(
                user_raw_data.get("id"),
            )
        )
        # self._logger.info(user_raw_data)

        # Look for existing contact, and patch instead of post
        r = requests.get(
            # Maybe we should url escape this, but as it comes from the identity server we trust it
            self._crm_url
            + "/Api/index.php/V8/module/Contacts?filter[iati_identityservice_id][eq]="
            + user_raw_data.get("id"),
            headers={"Authorization": "Bearer " + self._crm_access_token},
        )
        r.raise_for_status()
        user_existing_data = r.json()

        # Create new contact, or update existing one
        attributes = {
            "first_name": user_raw_data.get("name", {}).get("givenName"),
            "last_name": user_raw_data.get("name", {}).get("familyName"),
            # TODO probably want a few more here
        }
        if user_existing_data.get("data"):
            self._logger.info(
                " ... updating contact {}".format(user_existing_data["data"][0]["id"])
            )
            r = requests.patch(
                self._crm_url + "/Api/index.php/V8/module",
                headers={"Authorization": "Bearer " + self._crm_access_token},
                json={
                    "data": {
                        "type": "Contacts",
                        "id": user_existing_data["data"][0]["id"],
                        "attributes": attributes,
                    }
                },
            )
            r.raise_for_status()
        else:
            self._logger.info(" ... new contact")
            if self._error_if_crm_contact_not_exist:
                raise Exception(
                    "CRM Contact for user {} does not already exist".format(
                        user_raw_data.get("id")
                    )
                )
            else:
                attributes["iati_identityservice_id"] = user_raw_data.get("id")
                r = requests.post(
                    self._crm_url + "/Api/index.php/V8/module",
                    headers={"Authorization": "Bearer " + self._crm_access_token},
                    json={"data": {"type": "Contacts", "attributes": attributes}},
                )
                r.raise_for_status()


if __name__ == "__main__":
    # Logging to std out
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    root.addHandler(handler)
    # Go!
    sync = Sync(
        identity_service_url=os.getenv(
            "IDENTITY_SERVICE_URL", "https://localhost:9443"
        ),
        identity_service_allow_self_signed_https=bool(
            int(os.getenv("IDENTITY_SERVICE_ALLOW_SELF_SIGNED_HTTPS", "0"))
        ),
        identity_service_client_id=os.getenv("IDENTITY_SERVICE_CLIENT_ID"),
        identity_service_client_secret=os.getenv("IDENTITY_SERVICE_CLIENT_SECRET"),
        identity_service_paging=int(os.getenv("IDENTITY_SERVICE_PAGING", "100")),
        crm_url=os.getenv("CRM_URL", "http://localhost:8080"),
        crm_client_id=os.getenv("CRM_CLIENT_ID"),
        crm_client_secret=os.getenv("CRM_CLIENT_SECRET"),
        error_if_crm_contact_not_exist=bool(
            int(os.getenv("ERROR_IF_CRM_CONTACT_NOT_EXIST", "1"))
        ),
    )
    sync.sync()
