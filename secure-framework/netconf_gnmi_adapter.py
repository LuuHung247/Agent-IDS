#!/usr/bin/env python3
"""
3S-NOS NETCONF-gNMI Adapter

Overrides ZEP-DN's netconf_gnmi_adapter.py via sys.path priority.
Translates NETCONF edit-config → gNMI Set targeting nos-acl-bridge gNMI
server on each LEAF (port 9339, mTLS).

Bridge spec (verified 2026-04-26):
  - gNMI path:  /nos-iptables:acl/rule[rule-id=...]
  - YANG model: nos-iptables (namespace urn:3snos:iptables)
  - Fields:     rule-id, action (ACCEPT|DROP|RETURN), src-ip, dst-ip,
                protocol, src-port, dst-port, priority, source, comment,
                ttl-seconds
  - RBAC by client cert OU:
      internal/sdnc → ADMIN  (full CRUD)
      aws           → OPERATOR (no delete)
      auto          → AGENT  (only action=DROP + source=agent)

SF does NOT talk to SONiC telemetry :8080 — translib cannot handle custom
YANG write, and telemetry runs --noTLS (separate Phase 2 issue).

Supports two NETCONF XML formats from SDNC:
  1. nos-iptables (urn:3snos:iptables) — native 3S-NOS format
  2. OpenConfig ACL — translated automatically

Zone routing: src-ip → ip_to_leaf() → correct LEAF bridge client.
AGENT auto-stamp: if session is AGENT role, force action=DROP + source=agent.
"""

import json
import xml.sax.saxutils as saxutils
from lxml import etree
from typing import Optional, Dict, Any
import logging

from gnmi.gnmiclient import SonicGnmiClient
from tamper_logger import get_tamper_logger
from nos_gnmi_pool import NosGnmiConnectionPool, ip_to_leaf
from sam.role_policy import SonicRole, OnapRole
from sam.session_context import _session_local

logger = logging.getLogger(__name__)

_nos_pool: Optional[NosGnmiConnectionPool] = None

NS_NOS    = "urn:3snos:iptables"
NS_OC_ACL = "http://openconfig.net/yang/acl"

VALID_ACTIONS   = {"ACCEPT", "DROP", "RETURN"}
VALID_PROTOCOLS = {"tcp", "udp", "icmp", "all"}
VALID_SOURCES   = {"manual", "sdnc", "agent"}


def _current_onap_role() -> Optional[OnapRole]:
    ctx = getattr(_session_local, 'current', None)
    return ctx.onap_role if ctx else None


def _get_routed_client(role: SonicRole, src_ip: str) -> Optional[SonicGnmiClient]:
    if _nos_pool:
        return _nos_pool.get_client_for_zone(role, src_ip or "0.0.0.0/0")
    return None


class NetconfGnmiAdapter:
    """Same class name as ZEP-DN — picked up automatically when secure-framework/
    is first on sys.path."""

    def __init__(self, gnmi_client: SonicGnmiClient = None, session_context=None):
        self.gnmi_client = gnmi_client
        self.session_context = session_context
        self.tamper_logger = get_tamper_logger()

    # ── get-config / get ─────────────────────────────────────────────────────

    def handle_get_config(self, rpc_xml: etree.Element) -> str:
        try:
            self.tamper_logger.log("gnmi", "get_acl_rules",
                                   "Reading /nos-iptables:acl/rule via bridge", severity="info")
            client = self.gnmi_client
            if client is None or not client.connected:
                return "    <data/>"

            result = client.gc.get(
                path=["/nos-iptables:acl/rule"],
                encoding="json_ietf",
            )
            return self._gnmi_to_netconf_xml(result)
        except Exception as e:
            logger.error(f"handle_get_config: {e}")
            return "    <data/>"

    def handle_get(self, rpc_xml: etree.Element) -> str:
        return self.handle_get_config(rpc_xml)

    # ── edit-config ──────────────────────────────────────────────────────────

    def handle_edit_config(self, rpc_xml: etree.Element) -> str:
        try:
            message_id = rpc_xml.get('message-id', '1')

            config_elems = rpc_xml.xpath(
                './/*[local-name()="config"]',
                namespaces={'nc': 'urn:ietf:params:xml:ns:netconf:base:1.0'}
            )
            if not config_elems:
                return self._ok(message_id)

            config = config_elems[0]

            # nos-iptables namespace first
            acl_root = config.xpath(
                f'.//*[namespace-uri()="{NS_NOS}" and local-name()="acl"]'
            )
            if acl_root:
                return self._handle_nos_acl(acl_root[0], message_id)

            # OpenConfig ACL fallback
            oc_sets = config.xpath('.//*[local-name()="acl-sets"]')
            if oc_sets:
                return self._handle_openconfig_acl(config, message_id)

            logger.warning("edit-config: no recognisable payload")
            return self._ok(message_id)

        except Exception as e:
            logger.error(f"handle_edit_config: {e}")
            import traceback
            traceback.print_exc()
            msg_id = rpc_xml.get('message-id', '1')
            return self._error(msg_id, 'application', 'operation-failed', str(e))

    # ── nos-iptables native path ──────────────────────────────────────────────

    def _handle_nos_acl(self, acl_root: etree.Element, message_id: str) -> str:
        rules = acl_root.xpath('.//*[local-name()="rule"]')
        if not rules:
            return self._ok(message_id)

        for rule_elem in rules:
            operation = rule_elem.get('{urn:ietf:params:xml:ns:netconf:base:1.0}operation', 'merge')
            rule_id = self._text(rule_elem, 'rule-id')
            if not rule_id:
                return self._error(message_id, 'application', 'invalid-value', 'Missing rule-id')

            if operation in ('delete', 'remove'):
                err = self._delete_rule(rule_id, message_id)
                if err:
                    return err
                continue

            rule_data = {
                "rule-id":     rule_id,
                "action":      (self._text(rule_elem, 'action') or 'DROP').upper(),
                "src-ip":      self._text(rule_elem, 'src-ip')      or "",
                "dst-ip":      self._text(rule_elem, 'dst-ip')      or "",
                "protocol":    (self._text(rule_elem, 'protocol')   or 'all').lower(),
                "src-port":    self._text(rule_elem, 'src-port')    or "",
                "dst-port":    self._text(rule_elem, 'dst-port')    or "",
                "priority":    int(self._text(rule_elem, 'priority') or 1000),
                "source":      (self._text(rule_elem, 'source')     or 'sdnc').lower(),
                "comment":     self._text(rule_elem, 'comment')     or "",
                "ttl-seconds": int(self._text(rule_elem, 'ttl-seconds') or 0),
            }

            err = self._validate_and_push(rule_id, rule_data, message_id)
            if err:
                return err

        return self._ok(message_id)

    # ── OpenConfig ACL compatibility path ─────────────────────────────────────

    def _handle_openconfig_acl(self, config: etree.Element, message_id: str) -> str:
        """Translate OpenConfig ACL XML → nos-iptables/acl/rule (SDNC compat)."""
        acl_sets = config.xpath('.//*[local-name()="acl-sets"]')
        if not acl_sets:
            return self._ok(message_id)
        acl_set_list = acl_sets[0].xpath('.//*[local-name()="acl-set"]')
        if not acl_set_list:
            return self._ok(message_id)

        acl_set = acl_set_list[0]
        operation = acl_set.get('{urn:ietf:params:xml:ns:netconf:base:1.0}operation', 'merge')
        name_elem = acl_set.xpath('.//*[local-name()="name"]')
        table_name = name_elem[0].text if name_elem else 'unnamed'

        if operation == 'delete':
            return self._delete_rule(table_name, message_id) or self._ok(message_id)

        entries = acl_set.xpath('.//*[local-name()="acl-entry"]')
        if not entries:
            return self._ok(message_id)

        for entry in entries:
            seq_id     = self._text(entry, 'sequence-id') or '1000'
            action_raw = (self._text(entry, 'forwarding-action') or 'DROP').split(':')[-1].upper()
            src_ip     = self._text(entry, 'source-address') or ""
            dst_ip     = self._text(entry, 'destination-address') or ""
            proto_raw  = (self._text(entry, 'protocol') or 'all').upper()
            dst_port   = self._text(entry, 'destination-port') or ""
            src_port   = self._text(entry, 'source-port') or ""

            proto_map = {
                'IP_TCP': 'tcp', 'IP_UDP': 'udp', 'IP_ICMP': 'icmp',
                'TCP': 'tcp', 'UDP': 'udp', 'ICMP': 'icmp',
                '6': 'tcp', '17': 'udp', '1': 'icmp',
            }
            protocol = proto_map.get(proto_raw, 'all')

            # OC REJECT → bridge doesn't support; fall back to DROP
            if action_raw not in VALID_ACTIONS:
                action_raw = 'DROP'

            rule_id = f"{table_name}-{seq_id}"
            rule_data = {
                "rule-id":     rule_id,
                "action":      action_raw,
                "src-ip":      src_ip,
                "dst-ip":      dst_ip,
                "protocol":    protocol,
                "src-port":    src_port,
                "dst-port":    dst_port,
                "priority":    int(seq_id) if seq_id.isdigit() else 1000,
                "source":      "sdnc",
                "comment":     f"oc-acl:{table_name}",
                "ttl-seconds": 0,
            }

            err = self._validate_and_push(rule_id, rule_data, message_id)
            if err:
                return err

        return self._ok(message_id)

    # ── Validate + push ───────────────────────────────────────────────────────

    def _validate_and_push(self, rule_id: str, data: dict, message_id: str) -> Optional[str]:
        # Schema sanity
        if data["action"] not in VALID_ACTIONS:
            return self._error(message_id, 'application', 'invalid-value',
                               f"Invalid action '{data['action']}'. Allowed: {VALID_ACTIONS}")
        if data["protocol"] not in VALID_PROTOCOLS:
            return self._error(message_id, 'application', 'invalid-value',
                               f"Invalid protocol '{data['protocol']}'. Allowed: {VALID_PROTOCOLS}")
        if data["source"] not in VALID_SOURCES:
            return self._error(message_id, 'application', 'invalid-value',
                               f"Invalid source '{data['source']}'. Allowed: {VALID_SOURCES}")

        # AGENT auto-stamp + DROP-only enforcement (defense in depth; bridge also enforces)
        onap_role = _current_onap_role()
        if onap_role == OnapRole.AGENT:
            if data["action"] != 'DROP':
                msg = f"AGENT role may only push DROP rules (got {data['action']})"
                self.tamper_logger.log("security", "agent_action_blocked", msg, severity="warning")
                return self._error(message_id, 'application', 'access-denied', msg)
            data["source"] = "agent"  # auto-stamp source for AGENT
            if not data["comment"]:
                data["comment"] = f"agent:{rule_id}"

        return self._push_rule(rule_id, data, data["src-ip"], message_id)

    # ── gNMI Set / Delete to bridge ───────────────────────────────────────────

    def _push_rule(self, rule_id: str, data: dict, src_ip: str, message_id: str) -> Optional[str]:
        """Write rule via bridge gNMI Set on path /nos-iptables:acl/rule[rule-id=...]"""
        sonic_role = SonicRole.ADMIN  # writes always need admin gNMI cert

        client = _get_routed_client(sonic_role, src_ip)
        if client is None:
            client = self.gnmi_client

        if client is None or not client.connected:
            return self._error(message_id, 'application', 'operation-failed',
                               'No gNMI connection available')

        # Bridge expects JSON value at path /nos-iptables:acl/rule[rule-id=<id>]
        path = f"/nos-iptables:acl/rule[rule-id={rule_id}]"

        # Drop empty fields — bridge validators reject "" for inet:ipv4-prefix etc.
        clean = {k: v for k, v in data.items() if v not in (None, "")}

        try:
            client.gc.set(
                update=[(path, clean)],
                encoding='json_ietf',
            )
            logger.info(f"✓ Pushed {path} → {client.host}")
            self.tamper_logger.log_data_modification(
                event_type="gnmi",
                action="push_acl_rule",
                details=f"Pushed rule {rule_id} → bridge@{client.host}",
                user_identity=self._identity(),
                request_data=clean,
                data_before=None,
                data_after=clean,
                success=True,
            )
            return None
        except Exception as e:
            logger.error(f"gNMI Set failed for {rule_id}: {e}")
            self.tamper_logger.log_data_modification(
                event_type="gnmi",
                action="push_acl_rule",
                details=f"Failed rule {rule_id}: {e}",
                user_identity=self._identity(),
                request_data=clean,
                success=False,
                error_msg=str(e),
            )
            return self._error(message_id, 'application', 'operation-failed', str(e))

    def _delete_rule(self, rule_id: str, message_id: str) -> Optional[str]:
        """Delete rule from BOTH LEAFs (broadcast — we don't know which one holds it)."""
        clients = []
        if _nos_pool:
            for leaf_ip in _nos_pool.leaves.values():
                c = _nos_pool.get_client_by_key(SonicRole.ADMIN, leaf_ip)
                if c:
                    clients.append(c)
        if not clients and self.gnmi_client and self.gnmi_client.connected:
            clients = [self.gnmi_client]

        if not clients:
            return self._error(message_id, 'application', 'operation-failed',
                               'No gNMI connection available for delete')

        path = f"/nos-iptables:acl/rule[rule-id={rule_id}]"
        errors = []
        for client in clients:
            try:
                client.gc.set(delete=[path])
                logger.info(f"✓ Deleted {path} on {client.host}")
            except Exception as e:
                errors.append(f"{client.host}: {e}")
        if errors:
            return self._error(message_id, 'application', 'operation-failed', '; '.join(errors))
        return None

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _text(elem: etree.Element, local_name: str) -> Optional[str]:
        children = elem.xpath(f'.//*[local-name()="{local_name}"]')
        if children and children[0].text:
            return children[0].text.strip()
        return None

    def _identity(self) -> dict:
        ctx = getattr(_session_local, 'current', None)
        if not ctx:
            return {}
        return {
            "cn": ctx.client_cn,
            "ip": ctx.client_addr[0] if ctx.client_addr else None,
            "onap_role": ctx.onap_role.value,
            "sonic_role": ctx.sonic_role.value,
        }

    def _gnmi_to_netconf_xml(self, gnmi_result: Any) -> str:
        try:
            data_str = json.dumps(gnmi_result, indent=2) if gnmi_result else "{}"
            escaped = saxutils.escape(data_str)
            return (f'    <data><acl xmlns="{NS_NOS}">'
                    f'<raw>{escaped}</raw></acl></data>')
        except Exception:
            return "    <data/>"

    def _ok(self, msg_id: str) -> str:
        return (f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" '
                f'message-id="{msg_id}">\n    <ok/>\n</rpc-reply>')

    def _error(self, msg_id: str, err_type: str, err_tag: str, err_msg: str = "") -> str:
        msg_part = f'<error-message>{saxutils.escape(err_msg)}</error-message>' if err_msg else ''
        return (f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" '
                f'message-id="{msg_id}">\n'
                f'    <rpc-error>\n'
                f'        <error-type>{err_type}</error-type>\n'
                f'        <error-tag>{err_tag}</error-tag>\n'
                f'        {msg_part}\n'
                f'    </rpc-error>\n</rpc-reply>')
