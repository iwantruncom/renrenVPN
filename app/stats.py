"""Collect per-user traffic through the sing-box V2Ray API.

Traffic collection requires a build with ``with_v2ray_api``. The protobuf
wire-format implementation covers only the messages used here, without a code
generation dependency. Message definitions follow
``experimental/v2rayapi/stats.proto``:

    message Stat              { string name = 1; int64 value = 2; }
    message QueryStatsRequest { string pattern = 1; bool reset = 2; }
    message QueryStatsResponse{ repeated Stat stat = 1; }

Wire format: https://protobuf.dev/programming-guides/encoding/
"""

# The registered gRPC service name differs from the proto package name.
QUERY_METHOD = '/v2ray.core.app.stats.command.StatsService/QueryStats'
# sing-box uses user>>>name>>>traffic>>>direction for user counters.
USER_PREFIX = 'user>>>'


def _varint(value):
    out = bytearray()
    while True:
        chunk = value & 0x7F
        value >>= 7
        out.append(chunk | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _read_varint(buf, pos):
    value = shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def _skip(buf, pos, wire_type):
    """Skip unknown protobuf fields to preserve forward compatibility."""
    if wire_type == 0:
        return _read_varint(buf, pos)[1]
    if wire_type == 1:
        return pos + 8
    if wire_type == 2:
        length, pos = _read_varint(buf, pos)
        return pos + length
    if wire_type == 5:
        return pos + 4
    raise ValueError(f'不认识的 protobuf wire type: {wire_type}')


def encode_query(pattern=USER_PREFIX, reset=True):
    body = bytearray()
    if pattern:
        raw = pattern.encode('utf-8')
        body += b'\x0a' + _varint(len(raw)) + raw          # field 1 (pattern), length-delimited
    if reset:
        body += b'\x10\x01'                                # field 2 (reset), varint true
    return bytes(body)


def _decode_stat(buf):
    name, value, pos = '', 0, 0
    while pos < len(buf):
        tag, pos = _read_varint(buf, pos)
        field, wire = tag >> 3, tag & 7
        if field == 1 and wire == 2:
            length, pos = _read_varint(buf, pos)
            name = buf[pos:pos + length].decode('utf-8', 'replace')
            pos += length
        elif field == 2 and wire == 0:
            value, pos = _read_varint(buf, pos)
        else:
            pos = _skip(buf, pos, wire)
    return name, value


def decode_stats(buf):
    """Decode statistics into ``(name, byte_count)`` pairs."""
    out, pos = [], 0
    while pos < len(buf):
        tag, pos = _read_varint(buf, pos)
        field, wire = tag >> 3, tag & 7
        if field == 1 and wire == 2:
            length, pos = _read_varint(buf, pos)
            out.append(_decode_stat(buf[pos:pos + length]))
            pos += length
        else:
            pos = _skip(buf, pos, wire)
    return out


def to_deltas(entries):
    """Aggregate user counters as ``{name: (uplink, downlink)}``.

    Client names exclude ``>>>``, so splitting counter names is unambiguous.
    """
    deltas = {}
    for name, value in entries:
        if not name.startswith(USER_PREFIX):
            continue
        parts = name.split('>>>')
        if len(parts) != 4 or parts[2] != 'traffic':
            continue
        user, direction = parts[1], parts[3]
        up, down = deltas.get(user, (0, 0))
        if direction == 'uplink':
            deltas[user] = (up + value, down)
        elif direction == 'downlink':
            deltas[user] = (up, down + value)
    return deltas


def query(address, reset=True, timeout=5):
    """Read per-user counters as ``{name: (uplink, downlink)}``.

    With ``reset=True``, the returned values are deltas. Persist them before
    the next query to avoid losing traffic measurements.
    """
    import grpc          # Keep the optional dependency out of panel startup.

    with grpc.insecure_channel(address) as channel:
        call = channel.unary_unary(
            QUERY_METHOD,
            request_serializer=lambda payload: payload,
            response_deserializer=lambda payload: payload,
        )
        return to_deltas(decode_stats(call(encode_query(reset=reset), timeout=timeout)))
