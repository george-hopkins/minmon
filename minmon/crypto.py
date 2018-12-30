from collections import namedtuple


Context = namedtuple('Context', ['prepare', 'step', 'substitute'])


def context(context):
    if len(context) != 0x4170:
        raise RuntimeError()
    context = [int.from_bytes(context[i:i + 4], 'little') for i in range(0, len(context), 4)]
    return Context(
        prepare=context[:12],
        step=context[12:92],
        substitute=[context[i:i + 256] for i in range(92, len(context), 256)]
    )


def cipher(context, input):
    input = [int.from_bytes(input[i * 4:(i + 1) * 4], 'little') ^ context.prepare[i] for i in range(4)]
    prepared = []
    for i in range(4):
        p = 0
        for j in range(4):
            p ^= context.substitute[j][(input[i] >> (j * 8)) & 0xff]
            p ^= context.substitute[j + 8][(input[i] >> (j * 8)) & 0xff]
        prepared.append(p)

    step_a = [p ^ context.prepare[4 + i] for i, p in enumerate(prepared)]
    step_b = [p ^ context.prepare[8 + i] for i, p in enumerate(prepared)]
    for i in range(0, len(context.step), 8):
        step_a_next = []
        for j in range(4):
            a = context.step[i + j]
            for h in range(4):
                xor = step_a[(j - h + 1) % 4] ^ step_b[(j - h + 1) % 4] ^ step_a[(j - h) % 4]
                a ^= context.substitute[h + 8][(xor >> (h * 8)) & 0xff]
            step_a_next.append(a)

        step_b_next = []
        for j in range(4):
            b = context.step[i + j + 4]
            for h in range(4):
                xor_j = -(j + h) + j * 2
                xor = step_b[xor_j % 4] ^ step_a[(xor_j + 2) % 4] ^ step_b[(xor_j + 2) % 4] ^ step_a[(xor_j + 3) % 4] ^ step_b[(xor_j + 3) % 4]
                b ^= context.substitute[h + 12][(xor >> (h * 8)) & 0xff]
            step_b_next.append(b)

        step_a = step_a_next
        step_b = step_b_next

    output = b''
    for i in range(4):
        xor1 = step_a[(i - 1) % 4] ^ step_b[(i - 1) % 4] ^ step_a[(i - 2) % 4] ^ step_b[(i - 2) % 4] ^ step_b[(i) % 4]
        xor2 = step_a[i] ^ step_a[(i + 1) % 4] ^ step_b[(i + 1) % 4]
        o = 0
        for j in range(4):
            o ^= context.substitute[j + 4][(xor1 >> (j * 8)) & 0xff]
            o ^= context.substitute[j + 8][(xor2 >> (j * 8)) & 0xff]
        output += o.to_bytes(4, 'little')
    return output


def block(context, iv, data):
    result = b''
    for i in range((len(data) + 15) // 16):
        block = data[i * 16:][:16]
        block += b'\0' * (16 - len(block))
        decrypted = cipher(context, block)
        result += bytes(decrypted[j] ^ iv[j] for j in range(16))
        iv = block
    if result[-1] > 16:
        raise Exception()
    return result[:-result[-1]]
