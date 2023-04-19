import requests
from datetime import date
from datetime import datetime

class CTIS():

    headers = {}
    url = ""

    def __init__(self, url: str, username: str, password: str):
        self.url = url
        self.CTIS_login(username, password)

    def do_req(self, url, json):
        response = requests.post(self.url + url, headers = self.headers, json = json)

        ok = True
        if response.status_code == 500: # TODO
            response = requests.post(self.url + url, headers = self.headers, json = json)
        if response.status_code == 201:
            if "relationships" in url:
                res = response.json()
            else:
                res = response.json()["_id"]
        elif response.status_code == 409:
            if "relationshipTypes" in url or "relationships" in url:
                res = response.json()
            else:
                res = response.json()["_error"]["message"]["_id"]
        else:
            res = response.json()
            ok = False

        return ok, res
    
    def add_relationship(self, rel_type, src, src_type, dst, dst_type):
        json_query = [
            {
                "confidence": 100,
                "relationship_type": rel_type,
                "source_ref": src,
                "source_type": src_type,
                "target_ref": dst,
                "target_type": dst_type,
                "type": "relationship"
            }
        ]

        return self.do_req("/relationships", json_query)

    def add_operation(self, name, description):
        json_query = [
            {
                "confidence": 100,
                "description": description,
                "first_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ"),
                "labels": ["ddos"],
                "name": name,
                "x-sources": [
                    {
                        "source_name": "default",
                        "classification": 0,
                        "releasability": 0,
                        "tlp": 0
                    }
                ]
            }
        ]

        return self.do_req("/x-operations", json_query)

    def add_intrusion_set(self, name):
        json_query = [
            {
                "confidence": 100,
                "name": name,
                "x-sources": [
                    {
                        "source_name": "default",
                        "classification": 0,
                        "releasability": 0,
                        "tlp": 0
                    }
                ]
            }
        ]

        return self.do_req("/intrusion-sets", json_query)

    def add_url(self, value):
        json_query = [
            {
                "confidence": 100,
                "value": value,
                "x-sources": [
                    {
                        "source_name": "default",
                        "classification": 0,
                        "releasability": 0,
                        "tlp": 0
                    }
                ]
            }
        ]

        return self.do_req("/urls", json_query)

    def CTIS_login(self, user, password):
        #response = requests.post(f"{self.url}/api/auth/login", json={"username": user, "password": password})
        response = requests.get(f"{self.url}/login", auth=(user, password))
        self.headers = {'accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + response.json()["data"]["access_token"]}

    def upload(self, diffs, actor_name, op_name, op_desc):
        ok, intrusion_set = self.add_intrusion_set(actor_name)
        if not ok:
            raise Exception("Can't create intrusion set")
        ok, operation = self.add_operation(date.today().strftime('%Y%m%d') + ' ' + op_name, op_desc)
        if not ok:
            raise Exception("Can't create operation")
        ok, rel = self.add_relationship('attributed-to', operation, 'x-operations', intrusion_set, 'intrusion-sets')
        if not ok:
            raise Exception("Can't create operation - intrusion-set relationship")
        for url in diffs['added']:
            ok, url_id = self.add_url(url)
            if not ok:
                raise Exception(f"Can't create url {url}")
            ok, rel = self.add_relationship('related-to', operation, 'x-operations', url_id, 'urls')
            if not ok:
                raise Exception(f"Can't create operation - {url} relationship")

    def upload_slack2ctis(self, added, actor_name, op_name, op_desc):
        ok, intrusion_set = self.add_intrusion_set(actor_name)
        if not ok:
            raise Exception("Can't create intrusion set")
        ok, operation = self.add_operation(date.today().strftime('%Y%m%d') + ' ' + op_name, op_desc)
        if not ok:
            raise Exception("Can't create operation")
        ok, rel = self.add_relationship('attributed-to', operation, 'x-operations', intrusion_set, 'intrusion-sets')
        if not ok:
            raise Exception("Can't create operation - intrusion-set relationship")
        for url in added:
            url = url.strip(">").strip("<")
            ok, url_id = self.add_url(url)
            if not ok:
                raise Exception(f"Can't create url {url}")
            ok, rel = self.add_relationship('related-to', operation, 'x-operations', url_id, 'urls')
            if not ok:
                raise Exception(f"Can't create operation - {url} relationship")
