"""
Powergrid center of excellence in cyber security
Author: bhargavn@iisc.ac.in
CVE

"""

import json
import os
import pathlib
import pymongo as mon


class CveToDb:
    def __init__(self):
        self._client = mon.MongoClient("localhost", 27017)
        self._db = self._client["cveDB"]
        self._collection_cveList = self._db["cveListV5"]

    def get_all_documents(self):
        return self._collection_cveList.find()

    def parse_cve(self, record):
        _id = record.get("_id")
        _containers = record.get("containers").get("cna")
        res = self._get_containers(_containers, orig_container=_containers)
        for k, v in res.items():
            v.update({"_id": _id})
            self._db[k].insert_one(v)
        _cveMetadata = record.get("cveMetadata")
        _dataType = record.get("dataType")
        _dataVersion = record.get("dataVersion")

    def _get_containers(self, containers, primary_key="", _key="", result={}, orig_container=None):
        if isinstance(containers, dict):
            for k, v in containers.items():
                if primary_key == "":
                    primary_key = k
                else:
                    if containers == orig_container:
                        primary_key = k
                if result.get(primary_key) is None:
                    result.update({primary_key: {}})
                if isinstance(v, list):
                    for index, l in enumerate(v):
                        self._get_containers(l, primary_key, _key + k + str(index), result, orig_container)
                elif isinstance(v, dict):
                    self._get_containers(v, primary_key, _key + k, result, orig_container)
                else:
                    result[primary_key].update({_key + k: v})
        else:
            result[primary_key].update({_key: containers})
        return result


if __name__ == "__main__":
    obj = CveToDb()
    cursor = obj.get_all_documents()

    for doc in cursor:
        try:
            obj.parse_cve(doc)
        except RuntimeError as E:
            print(E, doc["_id"])
            continue
