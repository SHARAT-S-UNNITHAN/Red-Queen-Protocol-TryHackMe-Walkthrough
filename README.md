# Red Queen Protocol TryHackMe Walkthrough

**Author:** Sharat S Unnithan  
**Room:** Red Queen Protocol (TryHackMe)  
**Difficulty:** Easy  
**Connection:** VNC at `10.48.162.15:5901`  
**User:** `emp7749`  
**Password:** `R3dQu33n_7749!`

---

## Prologue

You wake up on a cold metal floor. Emergency lights bathe everything in red. The doors are sealed. A wall terminal flashes a single line:

```
Lockdown initiated. Red Queen Protocol in effect.
```

An AI called the Red Queen runs this underground research facility. Five terminals stand between you and the surface. Each one teaches a different reverse engineering technique.

---

## Table of Contents

1. Connecting to the Lab
2. Task 1 - Simple Analysis (hive_terminal)
3. Task 2 - Static Analysis (keypad)
4. Task 3 - Dynamic Analysis (override)
5. Task 4 - Symbolic Execution (memory_unlock)
6. Task 5 - Constraint Solving (memory_unlock angr)
7. Full Flag Summary
8. Key Takeaways

---

## 1. Connecting to the Lab

### Step 1: Start the Lab Machine

On the TryHackMe room page, click **Start Machine**. Wait 2-3 minutes.

### Step 2: Connect via VNC

```bash
vncviewer 10.48.162.15:5901
```

Password:

```
R3dQu33n_7749!
```

If TigerVNC prompts for a username, enter `emp7749`.

### Step 3: Open a Terminal

Once the desktop loads, open a terminal. Navigate to the recovered binaries:

```bash
cd ~/recovered_terminals
ls -la
```

You will see five files:

```
hive_terminal    keypad    memory_unlock    override    task5_solve.py    task5_underconstrain.py
```

---

## 2. Task 1 - Simple Analysis (hive_terminal)

### Theory

Reverse engineering starts with the cheapest possible question: "What plaintext data do you have?" When a developer writes a string literal in C, the compiler stores those bytes verbatim in the `.rodata` section. The `strings` tool scans the binary and prints every printable sequence.

### Supporting Tools

**`file`** — inspects magic bytes:

```bash
file ./hive_terminal
```

```
./hive_terminal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=2f972fcea000dde19b449129833854398c6516f8,
for GNU/Linux 3.2.0, not stripped
```

Tells us: 64-bit ELF, x86-64, PIE enabled, dynamically linked, **not stripped**.

**`xxd`** — dumps raw bytes:

```bash
xxd hive_terminal | head -n 1
```

```
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
```

The first four bytes `7f 45 4c 46` are the ELF magic signature.

**`checksec`** — reports security mitigations:

```bash
checksec --file=hive_terminal --format=json | jq
```

```json
{
  "hive_terminal": {
    "relro": "full",
    "canary": "yes",
    "nx": "yes",
    "pie": "yes",
    "symbols": "yes",
    "fortify_source": "yes"
  }
}
```

All standard mitigations enabled, but not stripped — symbol names remain visible, which helps later.

### Extract Strings

```bash
strings ./hive_terminal
```

Look for notable entries:

```bash
strings ./hive_terminal | grep "THM{"
```

Output:

```
THM{W3LC0ME_T0_TH3_H1V3}
```

### Answer

**Task 1 flag:**

```
THM{W3LC0ME_T0_TH3_H1V3}
```

The first door unlocks. The terminal beeps and the sealed door slides open.

---

## 3. Task 2 - Static Analysis (keypad)

### Theory

The `keypad` binary has no useful plaintext strings. The next step is **static analysis** — reading the disassembled instructions or decompiled pseudocode without running the binary. Ghidra turns assembly into readable C.

### Step 1: Open Ghidra

From the VNC desktop, launch Ghidra. The `keypad` binary is already imported. Run the default auto-analysis.

### Step 2: Navigate to `main`

In the Symbol Tree on the left:

1. Expand **Functions**
2. Double-click **main**

The decompiler shows a `strcmp` validation. The expected value comes from a `decode_code` function.

### Step 3: Open `decode_code`

Double-click `decode_code`. The decompiler shows something like:

```c
void decode_code(char *out) {
    char local_38[44];
    local_38[0]  = 0x0e;
    local_38[1]  = 0x12;
    local_38[2]  = 0x17;
    local_38[3]  = 0x21;
    ...
    for (int i = 0; i < 26; i++) {
        out[i] = local_38[i] ^ 0x5a;
    }
    out[26] = 0;
}
```

The logic XORs an encoded array with the key `0x5a`.

### XOR Theory

```
A XOR B = C
C XOR B = A

Encoded XOR Key = Plaintext
```

This is trivially reversible.

### Step 4: Extract the Encoded Bytes from objdump

Since Ghidra's decompiler presents the array nicely, we can also pull the bytes straight from `objdump`:

```bash
objdump -d ~/recovered_terminals/keypad | grep -A200 "<decode_code>:"
```

The encoded bytes are loaded via `movabs` into `%rsp`:

```
1201: movabs $0x81f120e2117120e,%rax
120b: movabs $0x141b05091b0d051f,%rdx
121e: movabs $0x1305141b05091b0d,%rax
1228: movabs $0x270e141f1e131914,%rdx
```

### Step 5: Decode with Python

```bash
python3 << 'EOF'
bytes_arr = [
    0x0e,0x12,0x17,0x21,0x0e,0x12,0x1f,0x08,0x1f,0x05,
    0x0d,0x1b,0x09,0x05,0x1b,0x14,0x05,0x13,0x14,0x19,
    0x13,0x1e,0x1f,0x14,0x0e,0x27
]
key = 0x5A
decoded = "".join(chr(b ^ key) for b in bytes_arr)
print("Decoded:", decoded)
EOF
```

Output:

```
Decoded: THM{THERE_WAS_AN_INCIDENT}
```

### Answer

**Task 2 flag:**

```
THM{THERE_WAS_AN_INCIDENT}
```

The second door slides open. The lights flicker. Something is wrong with the facility.

---

## 4. Task 3 - Dynamic Analysis (override)

### Theory

Some values only exist in memory at runtime. The `override` binary uses a changing key that increments with each character, making static reconstruction painful. **Dynamic analysis** with GDB lets you pause the program at any instruction and read register values directly.

### Step 1: Load GDB with GEF

```bash
cd ~/recovered_terminals
gdb ./override
```

GEF auto-loads:

```
GEF for linux ready, type `gef' to start, `gef config' to configure
```

### Step 2: Disassemble `main`

```
disassemble main
```

Look for the `strcmp` call:

```
0x000055555555531e <+174>:  call   0x5555555550e0 <strcmp@plt>
```

### Step 3: Set Breakpoint

Because PIE is enabled but GDB disables ASLR, the address is stable:

```
b *0x000055555555531e
```

### Step 4: Run and Input Any Value

```
run
```

At the prompt `Enter Override Code:` type:

```
test
```

### Step 5: Inspect Registers

At the GEF prompt:

```
x/s $rdi
x/s $rsi
```

`rsi` holds the expected value — the flag.

Alternatively:

```
regs
info registers rdi rsi
```

### Answer

**Task 3 flag** (from `$rsi`):

```
THM{1NCR3M3NT4L_K3Y}
```

The override console accepts the code. The inner vault door opens.

---

## 5. Task 4 - Symbolic Execution (memory_unlock) — Static View

### Theory

Some binaries hold no plaintext string and no single runtime point with the answer. Instead, the answer is whatever satisfies every constraint the program checks. **Symbolic execution** treats the program as a system of equations and asks an SMT solver to find input that makes all conditions true.

The `memory_unlock` binary has a `validate` function that checks your input byte by byte against a chain of constraints.

### Step 1: Open `memory_unlock` in Ghidra

Look at the `validate` function. You will see a series of comparisons and arithmetic operations that build up the expected value.

### Step 2: Decode the Logic

The validation builds each expected character from arithmetic operations. For example:

```c
if (input[0] != 'T') return 0;
if (input[1] != 'H') return 0;
if (input[2] != 'M') return 0;
if (input[3] != '{') return 0;
...
```

Or the checks may be more indirect, using XOR or addition with constants.

### Step 3: Reconstruct the Flag

Following the arithmetic, the flag is:

```
THM{LOCKDOWN_PROTOCOLS_INITIATED}
```

### Answer

**Task 4 flag:**

```
THM{LOCKDOWN_PROTOCOLS_INITIATED}
```

The main terminal accepts the override. Memory files begin decrypting.

---

## 6. Task 5 - Constraint Solving (memory_unlock angr)

### Theory

The final door's password is not stored anywhere. It is the unique input satisfying every constraint in `validate`. angr handles this by tracking symbolic bytes and exploring every path until one reaches the success branch.

### Step 1: Read the Solver Script

```bash
cat ~/recovered_terminals/task5_solve.py
```

It creates one symbolic byte per expected character, feeds them as input, and explores until the success path is reached.

### Step 2: Run the Solver

```bash
cd ~/recovered_terminals
python3 task5_solve.py
```

angr takes several minutes. Let it run without interruption.

### Step 3: Output

```
Solution: b'THM{I_REMEMBER_EVERYTHING}'
```

### Step 4: Run the Underconstrained Demo (Optional)

The room provides `task5_underconstrain.py` to demonstrate what happens when constraints are too loose:

```bash
python3 task5_underconstrain.py
```

Run it several times. It prints different valid solutions each time. Only the fully constrained `task5_solve.py` produces the intended flag.

### Answer

**Task 5 flag:**

```
THM{I_REMEMBER_EVERYTHING}
```

The surface door opens. Light floods the corridor.

---

## 7. Full Flag Summary

| Task | Binary | Technique | Flag |
|------|--------|-----------|------|
| 1 | hive_terminal | strings | `THM{W3LC0ME_T0_TH3_H1V3}` |
| 2 | keypad | Ghidra + XOR | `THM{THERE_WAS_AN_INCIDENT}` |
| 3 | override | GDB + GEF | `THM{1NCR3M3NT4L_K3Y}` |
| 4 | memory_unlock | Ghidra static analysis | `THM{LOCKDOWN_PROTOCOLS_INITIATED}` |
| 5 | memory_unlock | angr symbolic execution | `THM{I_REMEMBER_EVERYTHING}` |

---

## 8. Key Takeaways

### Technique Selection

| Technique | Tool | When to Use |
|-----------|------|-------------|
| Simple Analysis | `strings`, `xxd`, `file`, `checksec` | Data is in plaintext |
| Static Analysis | Ghidra, objdump, IDA | Logic is readable without running |
| Dynamic Analysis | GDB, GEF | Value exists in memory at runtime |
| Symbolic Execution | angr, Z3 | Many interdependent constraints |

### Method

1. Start with the cheapest technique that could plausibly work.
2. Escalate only when the previous layer comes up empty.
3. Recognize patterns (XOR, arithmetic, comparison chains).
4. Choose the layer where the answer actually lives.

### The Bigger Lesson

Reverse engineering is not one tool. It is the discipline of asking "how does this actually work?" and picking the right way to find out. Each technique targets a different layer of the binary:

- Plaintext lives in `.rodata`
- Logic lives in the disassembly
- Runtime state lives in registers
- Constraints live in the control flow graph

The Red Queen did not malfunction. There was an incident. You remember everything now.

---

**End of Walkthrough**

**Author:** Sharat S Unnithan

**Date:** October 2026
