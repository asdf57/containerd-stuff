#!/usr/bin/env python3

import json
import socket
import struct
import sys
from pathlib import Path

MAX_FRAME = 4 * 1024 * 1024

TTRPC_REQUEST  = 0x01
TTRPC_RESPONSE = 0x02

GRPC_OK            = 0
GRPC_NOT_FOUND     = 5
GRPC_UNIMPLEMENTED = 12


class ProtoError(Exception):
    pass


class RPCStatus(Exception):
    def __init__(self, code, message=""):
        self.code = code
        self.message = message
        super().__init__(f"RPC status {code}: {message}")


# ---------------------------------------------------------------------------
# Minimal protobuf encoder/decoder.
# We deliberately avoid requiring generated protobuf modules.
# ---------------------------------------------------------------------------

def enc_varint(value):
    if value < 0:
        value &= (1 << 64) - 1

    out = bytearray()

    while True:
        b = value & 0x7f
        value >>= 7

        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def dec_varint(data, pos):
    value = 0
    shift = 0

    while True:
        if pos >= len(data):
            raise ProtoError("truncated varint")

        b = data[pos]
        pos += 1

        value |= (b & 0x7f) << shift

        if not (b & 0x80):
            return value, pos

        shift += 7

        if shift >= 70:
            raise ProtoError("invalid varint")


def pb_varint(field, value):
    return enc_varint((field << 3) | 0) + enc_varint(value)


def pb_bytes(field, value):
    return (
        enc_varint((field << 3) | 2)
        + enc_varint(len(value))
        + value
    )


def pb_string(field, value):
    return pb_bytes(field, value.encode())


def fields(data):
    pos = 0

    while pos < len(data):
        key, pos = dec_varint(data, pos)

        field = key >> 3
        wire = key & 7

        if wire == 0:
            value, pos = dec_varint(data, pos)
            yield field, wire, value

        elif wire == 1:
            if pos + 8 > len(data):
                raise ProtoError("truncated fixed64")
            value = data[pos:pos + 8]
            pos += 8
            yield field, wire, value

        elif wire == 2:
            length, pos = dec_varint(data, pos)

            if pos + length > len(data):
                raise ProtoError("truncated bytes field")

            value = data[pos:pos + length]
            pos += length
            yield field, wire, value

        elif wire == 5:
            if pos + 4 > len(data):
                raise ProtoError("truncated fixed32")
            value = data[pos:pos + 4]
            pos += 4
            yield field, wire, value

        else:
            raise ProtoError(f"unsupported protobuf wire type {wire}")


# ---------------------------------------------------------------------------
# ttrpc Request / Response
# ---------------------------------------------------------------------------

def make_ttrpc_request(service, method, payload, timeout_ns):
    # ttrpc.Request:
    #   string service       = 1
    #   string method        = 2
    #   bytes  payload       = 3
    #   int64  timeout_nano  = 4

    out = b""
    out += pb_string(1, service)
    out += pb_string(2, method)
    out += pb_bytes(3, payload)

    if timeout_ns:
        out += pb_varint(4, timeout_ns)

    return out


def parse_status(data):
    code = 0
    message = ""

    for field, wire, value in fields(data):
        if field == 1 and wire == 0:
            code = value
        elif field == 2 and wire == 2:
            message = value.decode(errors="replace")

    return code, message


def parse_ttrpc_response(data):
    status_code = 0
    status_message = ""
    payload = b""

    for field, wire, value in fields(data):
        if field == 1 and wire == 2:
            status_code, status_message = parse_status(value)

        elif field == 2 and wire == 2:
            payload = value

    if status_code != GRPC_OK:
        raise RPCStatus(status_code, status_message)

    return payload


def recv_exact(sock, count):
    out = bytearray()

    while len(out) < count:
        chunk = sock.recv(count - len(out))

        if not chunk:
            raise ConnectionError("shim closed connection")

        out.extend(chunk)

    return bytes(out)


def rpc(sock, stream_id, service, method, payload,
        local_timeout, request_timeout_ns=0):

    request = make_ttrpc_request(
        service,
        method,
        payload,
        request_timeout_ns,
    )

    # ttrpc frame:
    #   uint32 length     big endian
    #   uint32 stream ID  big endian
    #   uint8  type
    #   uint8  flags
    header = struct.pack(
        ">IIBB",
        len(request),
        stream_id,
        TTRPC_REQUEST,
        0,
    )

    sock.settimeout(local_timeout)
    sock.sendall(header + request)

    header = recv_exact(sock, 10)

    length, response_stream, msg_type, flags = struct.unpack(
        ">IIBB", header
    )

    if length > MAX_FRAME:
        raise ProtoError(f"oversized ttrpc frame: {length}")

    if response_stream != stream_id:
        raise ProtoError(
            f"unexpected stream ID {response_stream}, expected {stream_id}"
        )

    if msg_type != TTRPC_RESPONSE:
        raise ProtoError(
            f"unexpected ttrpc message type {msg_type}"
        )

    body = recv_exact(sock, length)

    return parse_ttrpc_response(body)


# ---------------------------------------------------------------------------
# Task protobufs
# ---------------------------------------------------------------------------

def task_id_request(container_id):
    # ConnectRequest / PidsRequest:
    # string id = 1
    return pb_string(1, container_id)


def parse_connect_response(data):
    shim_pid = 0
    task_pid = 0
    version = ""

    for field, wire, value in fields(data):
        if field == 1 and wire == 0:
            shim_pid = value
        elif field == 2 and wire == 0:
            task_pid = value
        elif field == 3 and wire == 2:
            version = value.decode(errors="replace")

    return shim_pid, task_pid, version


def parse_process_info(data):
    pid = 0

    for field, wire, value in fields(data):
        if field == 1 and wire == 0:
            pid = value

    return pid


def parse_pids_response(data):
    pids = []

    # PidsResponse:
    # repeated ProcessInfo processes = 1
    for field, wire, value in fields(data):
        if field == 1 and wire == 2:
            pids.append(parse_process_info(value))

    return pids


# ---------------------------------------------------------------------------
# bootstrap.json
# ---------------------------------------------------------------------------

def load_bootstrap(bundle):
    path = Path(bundle) / "bootstrap.json"
    raw = path.read_bytes().strip()

    # containerd 2.x normally persists JSON here.
    try:
        obj = json.loads(raw)

        version = int(
            obj.get("version", obj.get("Version", 2))
        )

        address = obj.get(
            "address",
            obj.get("Address"),
        )

        protocol = obj.get(
            "protocol",
            obj.get("Protocol", "ttrpc"),
        )

        if not address:
            raise ValueError("bootstrap has no address")

        return version, address, protocol

    except (json.JSONDecodeError, UnicodeDecodeError):
        # Legacy runtime-v2 format: raw address, Task API v2, ttrpc.
        return 2, raw.decode().strip(), "ttrpc"


def socket_path(address):
    if address.startswith("unix://"):
        return address[len("unix://"):]

    if address.startswith("@"):
        return "\0" + address[1:]

    if address.startswith("\0"):
        return address

    # Legacy containerd behavior: no unix:// prefix means abstract UDS.
    return "\0" + address


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

def emit(classification, **kwargs):
    result = {"classification": classification}
    result.update(kwargs)
    print(json.dumps(result, sort_keys=True))


def probe(bundle, container_id, timeout):
    try:
        version, address, protocol = load_bootstrap(bundle)

    except Exception as e:
        emit("BOOTSTRAP_ERROR", error=str(e))
        return

    if protocol.lower() != "ttrpc":
        emit(
            "UNSUPPORTED_PROTOCOL",
            protocol=protocol,
            version=version,
        )
        return

    api_version = 3 if version >= 3 else 2

    while True:
        service = f"containerd.task.v{api_version}.Task"

        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)

        try:
            s.connect(socket_path(address))

        except socket.timeout:
            s.close()
            emit(
                "CONNECT_SOCKET_TIMEOUT",
                address=address,
                api_version=api_version,
            )
            return

        except Exception as e:
            s.close()
            emit(
                "CONNECT_SOCKET_ERROR",
                address=address,
                api_version=api_version,
                error=str(e),
            )
            return

        #
        # Connect/PID
        #
        # Vulnerable containerd *does* bound this operation with loadTimeout,
        # so give the request a real ttrpc deadline too.
        #
        try:
            connect_payload = rpc(
                s,
                1,
                service,
                "Connect",
                task_id_request(container_id),
                timeout,
                int(timeout * 1_000_000_000),
            )

            shim_pid, task_pid, shim_version = \
                parse_connect_response(connect_payload)

        except RPCStatus as e:
            s.close()

            # Match containerd's v3 -> v2 downgrade behavior.
            if (
                api_version == 3
                and e.code == GRPC_UNIMPLEMENTED
            ):
                api_version = 2
                continue

            emit(
                "CONNECT_RPC_ERROR",
                api_version=api_version,
                status=e.code,
                error=e.message,
            )
            return

        except socket.timeout:
            s.close()
            emit(
                "CONNECT_RPC_TIMEOUT",
                api_version=api_version,
            )
            return

        except Exception as e:
            s.close()
            emit(
                "CONNECT_RPC_ERROR",
                api_version=api_version,
                error=str(e),
            )
            return

        #
        # Pids
        #
        # IMPORTANT:
        #
        # request_timeout_ns = 0 intentionally.
        #
        # That mirrors the affected containerd load path, where the Pids()
        # invocation inherited an unbounded context. Our LOCAL socket timeout
        # prevents this audit program from hanging forever.
        #
        try:
            pids_payload = rpc(
                s,
                3,
                service,
                "Pids",
                task_id_request(container_id),
                timeout,
                0,
            )

            pids = parse_pids_response(pids_payload)

            s.close()

            if pids:
                emit(
                    "LIVE",
                    api_version=api_version,
                    shim_pid=shim_pid,
                    task_pid=task_pid,
                    shim_version=shim_version,
                    pids=pids,
                )
            else:
                emit(
                    "PIDS_EMPTY",
                    api_version=api_version,
                    shim_pid=shim_pid,
                    task_pid=task_pid,
                    shim_version=shim_version,
                    pids=[],
                )

            return

        except RPCStatus as e:
            s.close()

            if e.code == GRPC_NOT_FOUND:
                emit(
                    "PIDS_NOT_FOUND",
                    api_version=api_version,
                    shim_pid=shim_pid,
                    task_pid=task_pid,
                    status=e.code,
                )
            else:
                emit(
                    "PIDS_RPC_ERROR",
                    api_version=api_version,
                    shim_pid=shim_pid,
                    task_pid=task_pid,
                    status=e.code,
                    error=e.message,
                )

            return

        except socket.timeout:
            s.close()

            emit(
                "PIDS_TIMEOUT",
                api_version=api_version,
                shim_pid=shim_pid,
                task_pid=task_pid,
            )
            return

        except Exception as e:
            s.close()

            emit(
                "PIDS_RPC_ERROR",
                api_version=api_version,
                shim_pid=shim_pid,
                task_pid=task_pid,
                error=str(e),
            )
            return


def main():
    if len(sys.argv) not in (3, 4):
        print(
            f"usage: {sys.argv[0]} BUNDLE ID [TIMEOUT_SECONDS]",
            file=sys.stderr,
        )
        sys.exit(2)

    bundle = sys.argv[1]
    container_id = sys.argv[2]
    timeout = float(sys.argv[3]) if len(sys.argv) == 4 else 3.0

    probe(bundle, container_id, timeout)


if __name__ == "__main__":
    main()

















#!/usr/bin/env bash
set -uo pipefail

ROOT=/run/containerd/io.containerd.runtime.v2.task
PROBE=/usr/local/libexec/shim-ttrpc-probe.py
TIMEOUT=3

# Audit only while containerd is stopped.
if pgrep -x containerd >/dev/null; then
    echo "ERROR: containerd is running; refusing audit" >&2
    exit 2
fi

shopt -s nullglob

found=0
unknown=0

for bundle in "$ROOT"/*/*; do
    [[ -d "$bundle" ]] || continue

    ns=$(basename "$(dirname "$bundle")")
    id=$(basename "$bundle")

    # Ignore directories containerd itself ignores.
    [[ "$ns" == .* || "$id" == .* ]] && continue

    #
    # Kubernetes-specific hint.
    #
    # This is useful, but NOT treated as authoritative sandbox-store state.
    #
    kind="$(
        jq -r \
          '.annotations["io.kubernetes.cri.container-type"] // "unknown"' \
          "$bundle/config.json" 2>/dev/null
    )"

    [[ -n "$kind" ]] || kind=unknown

    result="$("$PROBE" "$bundle" "$id" "$TIMEOUT" 2>&1)"
    rc=$?

    if (( rc != 0 )); then
        echo "UNKNOWN $ns/$id: probe failed: $result"
        unknown=1
        continue
    fi

    class=$(jq -r '.classification' <<<"$result" 2>/dev/null)

    case "$class" in
        LIVE)
            pids=$(jq -r '.pids | join(",")' <<<"$result")
            echo "OK      $ns/$id type=$kind pids=$pids"
            ;;

        PIDS_TIMEOUT)
            #
            # This one is directly dangerous:
            #
            # affected containerd calls Pids() without the outer load
            # deadline, so this shim can itself wedge loadShims().
            #
            echo "BROKEN  $ns/$id type=$kind: Task.Pids DOES NOT RESPOND"
            found=1
            ;;

        PIDS_EMPTY|PIDS_NOT_FOUND)
            #
            # If containerd considers this ID non-sandbox, affected
            # containerd proceeds directly to Task.Delete().
            #
            case "$kind" in
                container)
                    echo "RISK    $ns/$id: NON-SANDBOX + $class -> containerd WILL ENTER Task.Delete"
                    ;;
                sandbox)
                    echo "REVIEW  $ns/$id: sandbox annotation + $class; Delete path depends on sandboxStore"
                    ;;
                *)
                    echo "REVIEW  $ns/$id: unknown type + $class; cannot exclude Task.Delete path"
                    ;;
            esac

            found=1
            ;;

        PIDS_RPC_ERROR)
            #
            # IMPORTANT FOR 2.2.2 / 2.3.1:
            #
            # shim.Pids() returns (nil, err).
            # len(nil) == 0.
            #
            # Therefore their old condition can still enter Delete for
            # a non-sandbox ID even though Pids returned an error.
            #
            if [[ "$kind" == "container" ]]; then
                echo "RISK    $ns/$id: Pids returned error; affected containerd can still enter Task.Delete"
            else
                echo "REVIEW  $ns/$id type=$kind: Pids returned error"
            fi

            echo "        $result"
            found=1
            ;;

        CONNECT_RPC_TIMEOUT|CONNECT_SOCKET_TIMEOUT)
            # Connect/PID had a load timeout in the affected code, so this
            # is not the exact #13848 Delete hang, but the shim is unhealthy.
            echo "UNHEALTHY $ns/$id type=$kind: $class"
            unknown=1
            ;;

        CONNECT_RPC_ERROR|CONNECT_SOCKET_ERROR|BOOTSTRAP_ERROR|UNSUPPORTED_PROTOCOL)
            echo "UNKNOWN $ns/$id type=$kind: $result"
            unknown=1
            ;;

        *)
            echo "UNKNOWN $ns/$id type=$kind: unexpected probe result: $result"
            unknown=1
            ;;
    esac
done

echo

if (( found )); then
    echo "AUDIT: one or more shims can hit an unbounded affected startup path"
    exit 1
fi

if (( unknown )); then
    echo "AUDIT: no confirmed candidate, but one or more shims could not be proven safe"
    exit 2
fi

echo "AUDIT: no candidates found"
exit 0