from pwn import *

context.arch = 'amd64'


def calculate_modulo(mod: int, eq: int):
    for k in range(10000):
        return eq + k * mod


def byte_array_to_string(byte_array):
    return ''.join(byte.decode('ascii') for byte in byte_array)


def get_main(assembly_code):
    try:
        main_start = assembly_code.index(b'4012bf:')
        next_section_start = assembly_code.index(b'\n\n', main_start + 1)
        main_code = assembly_code[main_start:next_section_start]
        return main_code
    except ValueError:
        return "No 'main' function found in the given assembly code."


def get_next_block(code):
    next_section_start = code.index(b'00 00 00   ')
    return code[:next_section_start + 8]


def get_next_index(code):
    next_section_start = code.index(b'00 00 00   ')
    return code[next_section_start + 8:]


p = remote('surveillance.ctf', 8000)

p.sendlineafter(b'Surveillance Proxy Password: ', b"...")

trash = p.recvline()

b64elf = p.recvline()[:-1]

real_elf = b64d(b64elf)

with open('challenge_elf', 'wb') as fp:
    fp.write(real_elf)


def find_cmp_modulo(code):
    modulo_index = code.index(b'\tb9')
    value = code[modulo_index + 4:modulo_index + 4 + 11]
    value = value.split(b' ')[::-1]
    return int(byte_array_to_string(value), 16)


def find_cmp_eq(code):
    other_index = code.index(b'\t81 fa')
    value = code[other_index + 7:other_index + 7 + 11]
    value = value.split(b' ')[::-1]
    return int(byte_array_to_string(value), 16)


def is_modulo(code):
    try:
        return code.index(b'\tb91') is not None
    except ValueError:
        return False


def modulo_all(code):
    eq = find_cmp_eq(code)
    modulo_num = find_cmp_modulo(code)
    return calculate_modulo(mod=modulo_num, eq=eq)


def find_add_eq(code):
    start_index = code.index(b'\t05')
    value = code[start_index + 4:start_index + 4 + 11]
    value = value.split(b' ')[::-1]
    return int(byte_array_to_string(value), 16)


def find_eq_eq(code):
    start_index = code.index(b'\t3d')
    value = code[start_index + 4:start_index + 4 + 11]
    value = value.split(b' ')[::-1]
    return int(byte_array_to_string(value), 16)


def calculate(code):
    try:
        return modulo_all(code)
    except ValueError:
        print('not using modulo')
        num1 = find_add_eq(code)
        num2 = find_eq_eq(code)
        value = num2 - num1
        UINT_MAX = 0xFFFFFFFF

        if value < 0:
            return UINT_MAX + value + 1

        return value


def main():
    dump = process(['objdump', '-M', 'intel', '-d', './challenge_elf'])
    full_dump = dump.recvall()
    main_function = get_main(full_dump)

    code_1 = get_next_block(main_function)

    code_2_index = get_next_index(main_function)
    code_2 = get_next_block(code_2_index)

    code_3_index = get_next_index(code_2_index)
    code_3 = get_next_block(code_3_index)

    code_4_index = get_next_index(code_3_index)
    code_4 = get_next_block(code_4_index)

    code_5_index = get_next_index(code_4_index)
    code_5 = get_next_block(code_5_index)

    calculated_code1 = str(calculate(code_1)).zfill(10)
    calculated_code2 = str(calculate(code_2)).zfill(10)
    calculated_code3 = str(calculate(code_3)).zfill(10)
    calculated_code4 = str(calculate(code_4)).zfill(10)
    calculated_code5 = str(calculate(code_5)).zfill(10)

    code = calculated_code1 + calculated_code2 + calculated_code3 + calculated_code4 + calculated_code5

    print(code)
    b64code = b64e(code.encode('ascii'))

    p.sendline(b64code)

    line = p.recvline()

    if b'Good' in line:
        b64elf = p.recvline()[:-1]

        try:
            real_elf = b64d(b64elf)
            with open('challenge_elf', 'wb') as fp:
                fp.write(real_elf)
        except:
            print(b64elf)

        main()

    print(line)
    p.interactive()


main()
