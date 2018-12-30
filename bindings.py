import binascii
import hashlib
import json
import sys
import minmon.crypto
import minmon.pbi_pb2


def decrypt(context, encrypted):
    hashed = encrypted[:-32]
    actual_hash = hashlib.sha256(hashed).digest()
    expected_hash_a = minmon.crypto.cipher(context, encrypted[-32:-16])
    expected_hash_b = minmon.crypto.cipher(context, encrypted[-16:])
    if actual_hash != expected_hash_a + expected_hash_b:
        raise Exception('Invalid checksum')
    return minmon.crypto.block(context, hashed[:16], hashed[16:])


def parse_pbi(context, binary):
    container = minmon.pbi_pb2.UnsignedPbiData()
    if container.ParseFromString(binary) != len(binary):
        raise Exception()

    hashes = {}
    decrypted = decrypt(context, container.data.hashes.data)
    data = minmon.pbi_pb2.FileHashes()
    root = None
    if data.ParseFromString(decrypted) != len(decrypted):
        raise Exception()
    for f in data.files:
        if f.path == b'/':
            root = f.hash
        else:
            hashes[f.path] = binascii.unhexlify(f.hash)

    push_bindings = {}
    for i, block in enumerate(container.data.push):
        decrypted = decrypt(context, block.data)
        data = minmon.pbi_pb2.PushBindings()
        if data.ParseFromString(decrypted) != len(decrypted):
            raise Exception()
        push_bindings[i] = {}
        for j, b in enumerate(data.bindings):
            which = b.value.WhichOneof('value')
            if which == 'string':
                push_bindings[i][b.key] = b.value.string
            elif which == 'integer':
                push_bindings[i][b.key] = b.value.integer
            elif which == 'boolean':
                push_bindings[i][b.key] = b.value.boolean
            else:
                raise Exception()

    pull_bindings = {}
    for i, block in enumerate(container.data.pull):
        decrypted = decrypt(context, block.data)
        data = minmon.pbi_pb2.PullBindings()
        if data.ParseFromString(decrypted) != len(decrypted):
            raise Exception()
        for j, b in enumerate(data.bindings):
            pull_bindings[i * 16 + j] = b.value.string

    return root, hashes, push_bindings, pull_bindings


def serialize(value):
    if isinstance(value, bytes):
        return binascii.hexlify(value).decode()
    else:
        return value


def main(args):
    if len(args) < 2:
        print('Usage: bindings.py CONTEXT PBI', file=sys.stderr)
        return 1

    context = open(args[0], 'rb').read()
    context = minmon.crypto.context(context)

    pbi = open(args[1], 'rb').read()
    result = parse_pbi(context, pbi)

    print('{} file hashes'.format(len(result[1])))
    print('{} push bindings'.format(len(result[2])))
    print('{} pull bindings'.format(len(result[3])))

    if len(args) > 2:
        serialized = {
            'push_bindings': {i: {k.decode(): serialize(v) for k, v in d.items()} for i, d in result[2].items()},
            'pull_bindings': {k: serialize(v) for k, v in result[3].items()},
        }
        json.dump(serialized, open(args[2], 'w'))
        print('Saved to {}'.format(args[2]))

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
