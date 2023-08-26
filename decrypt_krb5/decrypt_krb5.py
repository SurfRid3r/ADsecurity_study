from scapy.all import *
from scapy.layers.inet import UDP, TCP, IP
from scapy.layers import kerberos
from impacket.krb5 import keytab
from scapy.libs.rfc3961 import Key
from binascii import hexlify
import argparse

# patch
EncKDCRepPart = ASN1F_SEQUENCE(
    ASN1F_PACKET("key", None, kerberos.EncryptionKey, explicit_tag=0xA0),
    ASN1F_SEQUENCE_OF("lastReq", [], kerberos.LastReqItem, explicit_tag=0xA1),
    kerberos.UInt32("nonce", 0, explicit_tag=0xA2),
    ASN1F_optional(
        kerberos.KerberosTime("keyExpiration", GeneralizedTime(), explicit_tag=0xA3),
    ),
    kerberos.KerberosFlags(
        "flags",
        0,
        kerberos._TICKET_FLAGS,
        explicit_tag=0xA4,
    ),
    kerberos.KerberosTime("authtime", GeneralizedTime(), explicit_tag=0xA5),
    ASN1F_optional(
        kerberos.KerberosTime("starttime", GeneralizedTime(), explicit_tag=0xA6),
    ),
    kerberos.KerberosTime("endtime", GeneralizedTime(), explicit_tag=0xA7),
    ASN1F_optional(
        kerberos.KerberosTime("renewTill", GeneralizedTime(), explicit_tag=0xA8),
    ),
    kerberos.Realm("srealm", "", explicit_tag=0xA9),
    ASN1F_PACKET(
        "sname", kerberos.PrincipalName(), kerberos.PrincipalName, explicit_tag=0xAA
    ),
    ASN1F_optional(
        kerberos.HostAddresses("caddr", explicit_tag=0xAB),
    ),
    # RFC6806 sect 11
    ASN1F_optional(
        ASN1F_SEQUENCE_OF("encryptedPaData", [], kerberos.PADATA, explicit_tag=0xAC),
    ),
)


class EncASRepPart(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = kerberos.ASN1F_KRB_APPLICATION(
        EncKDCRepPart,
        implicit_tag=25,
    )


class EncTGSRepPart(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = kerberos.ASN1F_KRB_APPLICATION(
        EncKDCRepPart,
        implicit_tag=26,
    )


def lcm(*integers):
    a = integers[0]
    for b in integers[1:]:
        a = a * b
    return a


math.lcm = lcm


class DecryptKrb5:
    def __init__(self, keytab_file: str) -> None:
        # 解析keytab文件
        self.keys = keytab.Keytab.loadFile(keytab_file)

    # 根据principal,etype等参数获取hash密钥
    def get_key_from_keytab(
        self, principal: bytes, etype: ASN1_INTEGER, kvno: ASN1_INTEGER = None, **kwargs
    ):
        for k in self.keys.entries:
            # if k.deletd:
            #     continue
            if kvno and kvno != k.main_part["vno8"]:
                continue
            if (
                k.main_part["principal"].prettyPrint() == principal
                and k.main_part["keyblock"]["keytype"] == etype.val
            ):
                for c in kwargs.keys():
                    if (
                        isinstance(kwargs[c], int)
                        and k.main_part.get(c, None) != kwargs[c]
                    ):
                        continue
                return hexlify(k.main_part["keyblock"]["keyvalue"]["data"])
        return None

    # 解析过滤后的kerberos数据流
    def extract_kerberos_data(self, kerb_packets) -> dict:
        krb5_data = dict()
        for session_key, packets in kerb_packets.items():
            print(f"extracting Session: {session_key}")
            for p in packets:
                if p.haslayer(kerberos.Kerberos):
                    kerberos_data = self.extract_krb5_data(p)
                    if kerberos_data:
                        krb5_data[session_key] = kerberos_data
                        # print("Kerberos Data:", kerberos_data, "\n")
                else:
                    continue
        return krb5_data

    def extract_krb5_data(self, packet) -> dict:
        kerberos_data = packet[kerberos.Kerberos]
        if not kerberos_data.root.name:
            return None
        # else:
        #     print(kerberos_data.root.name, ": ")

        # 解析kerberos数据各通信阶段
        if kerberos_data.root.name in ["KRB_AS_REQ", "KRB_TGS_REQ"]:
            padata = kerberos_data.root.padata
            reqbody = kerberos_data.root.reqBody
            krb5_info = {
                "realm": reqbody.realm,  # str: Server's realm
                "cname": reqbody.cname,  # PrincipalName OPTIONAL
            }
            kerberos_data.root.padata = self.extract_padata(padata, krb5_info)

        elif kerberos_data.root.name in ["KRB_AS_REP", "KRB_TGS_REP"]:
            padata = kerberos_data.root.padata
            krb5_info = {
                "crealm": kerberos_data.root.crealm,
                "cname": kerberos_data.root.cname,
            }
            kerberos_data.root.padata = self.extract_padata(padata, krb5_info)
            enctickerpart = self.extract_encTicketpart(kerberos_data.root.ticket)
            # 解密 KDC_REP 中 ticket 内容
            kerberos_data.root.ticket.encPart = self.append_field(
                kerberos_data.root.ticket.encPart,
                "_decrtpy_encTicketpart",
                enctickerpart,
            )
            # 解密 KDC_REP 中 enc_part 内容
            kerberos_data.root.encPart = self.append_field(
                kerberos_data.root.encPart,
                "_decrtpy_encKDCRepPart",
                self.extract_encKDCRepPart(kerberos_data.root),
            )

        elif kerberos_data.root.name in ["KRB_AP_REQ", "KRB_ERROR", "KRB_AP_REP"]:
            pass

        return kerberos_data

    def extract_padata(self, padata: list, krb5_info: dict) -> kerberos.PADATA:
        if not padata:
            return None
        for i in range(0, len(padata)):
            padata_type = padata[i].padataType  # ASN1_INTEGER
            padata_value = padata[i].padataValue
            extract_type = kerberos._PADATA_TYPES[padata_type.val]
            # 需要用用户的hash密钥加密的到期时间
            if extract_type == "PA-ENC-TIMESTAMP":
                padata[i].padataValue = self.append_field(
                    padata[i].padataValue,
                    "_decrtpy_enc_timestamp",
                    self.extract_enc_timestamp(padata_value, krb5_info),
                )

            elif extract_type == "PA-TGS-REQ":
                enctickerpart = self.extract_encTicketpart(padata_value.ticket)
                padata[i].padataValue.ticket.encPart = self.append_field(
                    padata[i].padataValue.ticket.encPart,
                    "_decrtpy_encTicketpart",
                    enctickerpart,
                )

                # 使用会话密钥对authenticator解密
                # key_usage_number = 7
                # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator
                self.session_key = enctickerpart.key.toKey()
                padata[i].padataValue = self.append_field(
                    padata[i].padataValue,
                    "_decrtpy_authenticator",
                    padata_value.authenticator.decrypt(
                        self.session_key, key_usage_number=7, cls=kerberos.KRB_Authenticator
                    ),
                )

            elif extract_type in ["PA-PAC-REQUEST"]:
                # TODO
                pass

            elif extract_type in ["PA-ETYPE-INFO2", "PA-ETYPE-INFO", "PA-PW-SALT"]:
                # https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.7.3
                pass
        return padata

    # 根据keytab解密AS-REQ中pa_enc_timestamp内容
    def extract_enc_timestamp(
        self, padata_value, krb5_info: dict
    ) -> kerberos.PA_ENC_TS_ENC:
        domain_name = krb5_info["realm"].val.lower()
        user_name = b""
        # 1:NT-PRINCIPAL
        # 2:NT-SRV-INST
        if krb5_info["cname"].nameType.val in [1, 2]:
            user_name = krb5_info["cname"].nameString[0].val
            user_principal_name = user_name + b"@" + domain_name
            # 从keytab中获取密码,尝试进行解密
            # https://github.com/fortra/impacket/blob/impacket_0_11_0/impacket/krb5/kerberosv5.py#L249
            client_key = self.get_key_from_keytab(
                principal=user_principal_name,
                etype=padata_value.etype,
                kvno=padata_value.kvno,
            )
            k = Key(padata_value.etype.val, key=hex_bytes(client_key))
            # "PA-ENC-TIMESTAMP": 1
            return padata_value.decrypt(k)
        return None

    def extract_encTicketpart(
        self, ticket: kerberos.KRB_Ticket
    ) -> kerberos.EncTicketPart:
        """
        解密 ticket 中 enc-part 的内容
        """
        # 根据kbrtgt的密钥解密ticket内容
        # 1:NT-PRINCIPAL
        # 2:NT-SRV-INST
        if ticket.sname.nameType.val in [1, 2]:
            user_name = ticket.sname.nameString[0].val
            domain_name = ticket.sname.nameString[1].val
            server_principal_name = user_name + b"@" + domain_name.lower()
            server_key = self.get_key_from_keytab(
                server_principal_name, ticket.encPart.etype, ticket.encPart.kvno
            )
            # AS-REP Ticket and TGS-REP Ticket
            # keyusage = 2
            if not server_key:
                return None
            k = Key(ticket.encPart.etype.val, key=hex_bytes(server_key))
            # EncTicketPart
            encticketpart = ticket.encPart.decrypt(k)
            encticketpart.authorizationData = self.extract_AuthorizationData(
                encticketpart.authorizationData
            )
            return encticketpart
        return None

    def extract_encKDCRepPart(self, kdc_rep):
        """
        解密 KDCRepPart 中 enc-part 的内容
        """
        # 根据kbrtgt的密钥解密ticket内容
        # 1:NT-PRINCIPAL
        # 2:NT-SRV-INST
        if kdc_rep.cname.nameType.val in [1, 2]:
            user_name = kdc_rep.cname.nameString[0].val
            domain_name = kdc_rep.crealm.val.lower()
            client_principal_name = user_name + b"@" + domain_name.lower()
            # kvno = kdc_rep.encPart.kvno
            client_key = self.get_key_from_keytab(
                client_principal_name, kdc_rep.encPart.etype
            )
            # AS-REP Ticket and TGS-REP Ticket
            if isinstance(kdc_rep, kerberos.KRB_TGS_REP):
                # keyusage = 8
                k = self.session_key
            else:
                k = Key(kdc_rep.encPart.etype.val, key=hex_bytes(client_key))

            # EncTicketPart
            if isinstance(kdc_rep, kerberos.KRB_AS_REP):
                encticketpart = kdc_rep.encPart.decrypt(
                    k, key_usage_number=3, cls=EncASRepPart
                )
            elif isinstance(kdc_rep, kerberos.KRB_TGS_REP):
                k = self.session_key
                encticketpart = kdc_rep.encPart.decrypt(
                    k, key_usage_number=8, cls=EncTGSRepPart
                )
            else:
                encticketpart = kdc_rep.encPart.decrypt(k)
            return encticketpart

        return None

    # 解析AuthorizationData
    def extract_AuthorizationData(self, authorization_data: kerberos.AuthorizationData):
        for i in range(0, len(authorization_data.seq)):
            authorization_data.seq[i] = self.extract_AuthorizationData_item(
                authorization_data.seq[i]
            )
        return authorization_data

    def extract_AuthorizationData_item(self, item: kerberos.AuthorizationDataItem):
        # RFC4120 sect 7.5.4
        # AD-IF-RELEVANT:1
        # AD_MANDATORY_FOR_KDC:8
        if item.adType.val in [1, 8]:
            item.adData = self.extract_AuthorizationData(item.adData)
        # AD_KDC_ISSUED:4
        # AD_AND_OR:5
        elif item.adType.val in [4, 5]:
            item.adData.elements = self.extract_AuthorizationData(item.adData.elements)
        # AD_WIN2K_PAC:128
        elif item.adType.val == 128:
            pass
            # item.adData = self.extract_AD_WIN2K_PAC(item.adData)
        return item

    @staticmethod
    def append_field(field, name, value):
        field.fields_desc = field.fields_desc + [Field(name, "bytes")]
        field.fields[name] = value
        field.fieldtype[name] = value
        return field

    # 解析pcap文件并输出kerberos数据流
    def parse_pcap(self, pcap="kerberos.pcap"):
        packets = rdpcap(pcap)
        kerb_packets = dict()
        # filter kerberos packets
        # 四元组提取会话流量
        for p in packets:
            ip_src, ip_dst = p[IP].src, p[IP].dst
            if UDP in p:
                sport, dport = p[UDP].sport, p[UDP].dport
            elif TCP in p:
                sport, dport = p[TCP].sport, p[TCP].dport
            else:
                continue

            session_key = (ip_src, sport, ip_dst, dport)
            reverse_session_key = (ip_dst, dport, ip_src, sport)

            key = session_key if session_key in kerb_packets else reverse_session_key
            kerb_packets.setdefault(key, []).append(p)

        self.pkt_dict = self.extract_kerberos_data(kerb_packets)
        return self.pkt_dict
    
    def print(self):
        for session in self.pkt_dict.keys():
            print("Session ", session)
            self.pkt_dict[session].show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Decrypt Kerberos packets')
    parser.add_argument('keytab', help='keytab file')
    parser.add_argument('pcap', help='pcap file')
    args = parser.parse_args()

    d_krb5 = DecryptKrb5(args.keytab)
    krb5_result = d_krb5.parse_pcap(args.pcap)
    d_krb5.print()
    # d_krb5 = DecryptKrb5("1.keytab")
    # d_krb5.parse_pcap("kerberos.pcap")
    # d_krb5.print()



