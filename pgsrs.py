#!/usr/bin/python3
import os
import gzip
import sys
import uuid
import json
from datetime import datetime
from jwcrypto import jwe, jwk, jws
from jwcrypto.common import json_encode, json_decode
from io import IOBase

class psubstance(object):
    def __init__(self):
        self.verbose = ""
        self.bad_keys = ["_name", "_nameHTML", "_formulaHTML", "_approvalIDDisplay", "_isClassification","_self","approvedBy","created","createdBy","lastEdited","lastEditedBy","deprecated","uuid","originatorUuid","linkingID","id","documentDate","status","version"]
        self._obj = {}
        self._protected = []
        self._keyset = jwk.JWKSet()
        self._protected_headers  = {"alg": "RS256",
                                    "cty": "application/json",
                                    "kid": "",
                                    "ver": "3.0.2",
                                    "ori": "Unknown",
                                    "dat": datetime.now().isoformat()}

    def loads(self, substance):
        self._protected = []
        self._obj = json_decode(substance)
        self._protected_headers["ori"] = self._obj.get("_self", "Unknown")
        if self.verbose == "-v":
            print("Substance Origin: %s"%self._protected_headers["ori"])
            print("Substance cannot be Validated")
            print("Export Version: Unknown")
            print("Export Date: Unknown")

    def load(self, fh):
        if isinstance(fh, IOBase):
            self.loads(fh.read())
        elif isinstance(fh, str) and os.path.exists(fh):
            with open(fh, "r", encoding="UTF-8") as f:
                self.loads(f.read())

    def dumps(self, pretty=False):
        if pretty:
            return json.dumps(self._obj, sort_keys=True, indent=4)
        else:
            return json_encode(self._obj)

    def uuid2index(self):
        '''replace the references uuid with the index of the reference in the substances references list'''
        sobj = json_encode(self._obj)
        for idx in range(len(self._obj.get("references", []))):
            if "uuid" in self._obj["references"][idx]:
                sobj = sobj.replace(self._obj["references"][idx]["uuid"], str(idx))
        self._obj = json_decode(sobj)
        for r in self._obj["references"]:
            if "uuid" in r:
                del r["uuid"]

    def deleteValidationNotes(self):
        '''delete Validation Notes'''
        v_refs = []
        for idx in reversed(range(len(self._obj.get("notes", [])))):
            if self._obj["notes"][idx]["note"].startswith("[Validation]"):
                for r in self._obj["notes"][idx]["references"]:
                    if r not in v_refs:
                        v_refs.append(r)
                del self._obj["notes"][idx]
        if v_refs:
            o = self._obj.copy()
            del o["references"]
            sobj = json_encode(o)
            for idx in reversed(range(len(self._obj["references"]))):
                r_uuid = self._obj["references"][idx].get("uuid", "")
                if r_uuid in v_refs and r_uuid not in sobj:
                    del self._obj["references"][idx]

    def scrub(self, obj=None):
        '''remove bad_keys from the substances object'''
        if obj is None:
            obj = self._obj
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                if key == "uuid" and "docType" in obj:
                    self.scrub(obj[key])
                elif key in self.bad_keys:
                    del obj[key]
                elif obj[key] is None:
                    continue
                else:
                    self.scrub(obj[key])
        elif isinstance(obj, list):
            for i in reversed(range(len(obj))):
                if obj[i] is None:
                    continue
                self.scrub(obj[i])
        else:
            pass

    def find_protected(self, obj=None, parent="self._obj"):
        '''find protected elements'''
        if obj is None:
            obj = self._obj
        if isinstance(obj, dict):
            if "access" in obj and obj["access"]:
                self._protected.append(parent)
            for key in list(obj.keys()):
                if obj[key] is None:
                    continue
                self.find_protected(obj[key], "%s[\"%s\"]"%(parent, key))
        elif isinstance(obj, list):
            for i in reversed(range(len(obj))):
                if obj[i] is None:
                    continue
                self.find_protected(obj[i], "%s[%s]"%(parent, i))
        else:
            pass

    def get_private_key(self):
        for key in self._keyset["keys"]:
            if key.has_private:
                return key

    def encode_protected(self):
        '''encode protected elements'''
        protected_header = {
            "alg": "RSA-OAEP",
            "enc": "A256GCM",
            "typ": "JOSE+JSON",
            "kid": ""
        }
        private_key = self.get_private_key()
        for e in sorted(self._protected, key=len, reverse=True):
            o = eval(e)
            jwetoken = jwe.JWE(json_encode(o).encode("UTF-8"))
            if private_key is not None:
                protected_header["kid"] = private_key.get("kid")
                jwetoken.add_recipient(private_key, protected_header)
            for gr in o["access"]:
                key = self._keyset.get_key(gr)
                if key is not None:
                    protected_header["kid"] = key.get("kid")
                    jwetoken.add_recipient(key, protected_header)
            eval("%s.clear()"%e)
            eval("%s.update(json_decode(jwetoken.serialize(False)))"%e)

    def sign(self):
        key = self.get_private_key()
        if key is not None:
            jwstoken = jws.JWS(json_encode(self._obj).encode("UTF-8"))
            jwstoken.add_signature(key, None, json_encode(self._protected_headers))
            return jwstoken.serialize(True)
        else:
            return json_encode(self._obj).encode("UTF-8")

    def verify(self, signed):
        jwstoken = jws.JWS()
        jwstoken.deserialize(signed.decode("UTF-8"))
        print("Substance Origin: %s"%jwstoken.jose_header.get("ori", "Unknown"))
        try:
            jwstoken.verify(self._keyset.get_key(jwstoken.jose_header.get("kid")))
            if jwstoken.is_valid:
                self._obj = json_decode(jwstoken.payload)
                self._protected_headers["ori"] = jwstoken.jose_header.get("ori", "Unknown")
                if self.verbose == "-v":
                    print("Substance is Valid")
                    print("Export Version: %s"%jwstoken.jose_header.get("ver", "Unknown"))
                    print("Export Date: %s"%jwstoken.jose_header.get("dat", "Unknown"))
            else:
                if self.verbose == "-v":
                    print("Substance is not Valid")
        except Exception as e:
            if self.verbose == "-v":
                print("Substance is not Valid")
                print(e)
            self._obj = {}

    def decode(self, obj=None, parent="self._obj"):
        if obj is None:
            obj = self._obj
        if isinstance(obj, dict):
            if "ciphertext" in obj and obj["ciphertext"]:
                jwetoken = jwe.JWE()
                try:
                    jwetoken.deserialize(json_encode(obj), self.get_private_key())
                    eval("%s.clear()"%parent)
                    eval("%s.update(json_decode(jwetoken.payload))"%parent)
                except Exception as e:
                    print(e)
                    eval("%s.clear()"%parent)
            for key in list(obj.keys()):
                if obj[key] is None:
                    continue
                self.decode(obj[key], "%s[\"%s\"]"%(parent, key))
        elif isinstance(obj, list):
            for i in reversed(range(len(obj))):
                if obj[i] is None:
                    continue
                self.decode(obj[i], "%s[%s]"%(parent, i))
        else:
            pass

    def restoreRefs(self, obj=None):
        if obj is None:
            obj = self._obj
            for idx in reversed(range(len(self._obj.get("references", [])))):
                if self._obj["references"][idx]:
                    self._obj["references"][idx]["uuid"] = str(uuid.uuid4())
        if isinstance(obj, dict):
            if "references" in obj and obj != self._obj:
                for idx in reversed(range(len(obj.get("references",[])))):
                    if "uuid" in self._obj["references"][int(obj["references"][idx])]:
                        obj["references"][idx] = self._obj["references"][int(obj["references"][idx])]["uuid"]
                    else:
                        del obj["references"][idx]
            for key in list(obj.keys()):
                if obj[key] is None:
                    continue
                self.restoreRefs(obj[key])
        elif isinstance(obj, list):
            for i in reversed(range(len(obj))):
                if obj[i] is None:
                    continue
                self.restoreRefs(obj[i])
        else:
            pass

    def removeEmptyObjects(self, obj=None):
        if obj is None:
            obj = self._obj
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                if obj[key] == {}:
                    del obj[key]
                elif obj[key] is None:
                    continue
                else:
                    self.removeEmptyObjects(obj[key])
        elif isinstance(obj, list):
            for i in reversed(range(len(obj))):
                if obj[i] == {}:
                    del obj[i]
                elif obj[i] is None:
                    continue
                else:
                    self.removeEmptyObjects(obj[i])
        else:
            pass

    def load_keyset(self, fh):
        self._keyset = jwk.JWKSet()
        with open(fh, "r") as f:
            self._keyset.import_keyset(f.read())
        key = self.get_private_key()
        if key is not None:
            self._protected_headers["kid"] = key.get("kid")

def create_key_material():
    print("Creating kay materials for: NCATS, EMA and USP")
    keysets = []
    for kid in ["NCATS", "EMA", "USP"]:
        keysets.append(jwk.JWKSet())
        keysets[-1]["keys"].add(jwk.JWK.generate(kty="RSA", size=2048, kid=kid))
        if kid != "NCATS":
            keysets[0]["keys"].add(jwk.JWK(**keysets[-1].get_key(kid).export(False, True)))
            keysets[-1]["keys"].add(jwk.JWK(**keysets[0].get_key("NCATS").export(False, True)))
    for ks in keysets:
        for k in ks["keys"]:
            if k.has_private:
                with open("%s.jwks.json"%k.get("kid"), "w") as f:
                    f.write(ks.export(True, False))
                break

def usage():
    print("Usage: pgsrs.py <JWK Set set> <input file> <output file> [-v[v]]")
    print("       <JWK Set file> - NCATS|EMA|USP")
    print("       <input file>, <output file> - *.gsrs|*.gsrsp|*.gsrsps")
    print("           *.gsrs - standard .gsrs file")
    print("           *.gsrsp - portable file without signatures")
    print("           *.gsrsps - portable file with signatures")
    print("       -v - verbose")

def main():
    if len(sys.argv) < 4:
        usage()
        sys.exit(2)
    if sys.argv[1] not in ("NCATS", "EMA", "USP"):
        usage()
        sys.exit(2)
    if sys.argv[2][-5:] not in ("on.gz", ".gsrs", "gsrsp", "srsps"):
        usage()
        sys.exit(2)
    if sys.argv[3][-5:] not in (".gsrs", "gsrsp", "srsps"):
        usage()
        sys.exit(2)
    if not os.path.isfile("%s.jwks.json"%sys.argv[1]):
        create_key_material()
    s = psubstance()
    if len(sys.argv) == 5 and sys.argv[4].startswith("-v"):
        s.verbose = sys.argv[4]
    s.load_keyset("%s.jwks.json"%sys.argv[1])
    with gzip.open(sys.argv[2], "r") as inpf, gzip.open(sys.argv[3], "w") as outf:
        for line in inpf:
            if sys.argv[2].endswith(".gsrsps"):
                s.verify(line.strip())
            else:
                s.loads(line.strip())
            if not sys.argv[2].endswith(".gsrs") and not sys.argv[2].endswith("on.gz"):
                s.decode()
                s.restoreRefs()
                s.removeEmptyObjects()
            if not sys.argv[3].endswith(".gsrs"):
                s.deleteValidationNotes()
                s.uuid2index()
                s.scrub()
                s.find_protected()
                s.encode_protected()
            if s.verbose == "-vv":
                print(s.dumps(True))
            if sys.argv[3].endswith(".gsrsps"):
                out = s.sign()
            else:
                out = s.dumps()
            if out and out != "{}":
                outf.write(b"\t\t%s\n"%out.encode("utf-8"))

if __name__ == '__main__':
    main()
