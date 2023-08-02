[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkkent030315%2Frazy_importer.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkkent030315%2Frazy_importer?ref=badge_shield)
![crates.io](https://img.shields.io/crates/v/razy-importer.svg?label=crates.io:razy-importer)
![crates.io](https://img.shields.io/crates/v/razy-importer-macros.svg?label=crates.io:razy-importer-macros)

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkkent030315%2Frazy_importer.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkkent030315%2Frazy_importer?ref=badge_large)

# razy_importer

Rust implementation of [lazy_importer](https://github.com/JustasMasiulis/lazy_importer)

# Usage

```toml
razy-importer        = "0.3.2"
razy-importer-macros = "0.3.1"
```

Function prototype must be explicitly declared on the variable and this is by Rust design that Rust does not allow constants to be used where known type information is needed at compile time.

Since the implementation of the `ri_fn` macro takes `func_type` as an `Expr` type, this is treated as an expression that is resolved at runtime. However, types such as `extern "system" fn()`, which represents a function pointer, require known type information at compile time. Therefore, the type `Expr`, which is resolved at runtime, cannot be used directly as such a function type.

```rust
#[macro_use]
extern crate razy_importer_macros;

fn main() {
    let NtGetCurrentProcessorNumber: unsafe extern "system" fn() -> ULONG =
        ri_fn_m!("NtGetCurrentProcessorNumber", ri_mod!("ntdll.dll"));
    println!("NtGetCurrentProcessorNumber={}", unsafe { NtGetCurrentProcessorNumber() });
    let NtGetCurrentProcessorNumber: unsafe extern "system" fn() -> ULONG =
        ri_fn!("NtGetCurrentProcessorNumber");
    println!("NtGetCurrentProcessorNumber={}", unsafe { NtGetCurrentProcessorNumber() });
}
```

## Case Sensitivity

The crates `razy-importer` and `razy-importer-macros` has `case-sensitive` and which is set by default. A letter case will be ignored because Windows will not consider whether or not the letter is uppercase or lowercase.

In case you need to use strict case-sensitive check, disable the feature.

```toml
razy-importer = { version = "...", default_feature = false }
razy-importer-macros = { version = "...", default_feature = false }
```

# API Set DLLs is supported

API Set DLLs is supported (such as `SetProcessMitigationPolicy`) since `>=0.2.0`.

- Relation: `kernel32.dll` -> `api-ms-win-core-processthreads-l1-1-1.SetProcessMitigationPolicy`
- Relation: `api-ms-win-core-processthreads-l1-1-1.dll` -> `kernel32.SetProcessMitigationPolicy`

Windows has a concept known as "API Sets". Introduced starting from Windows 7, this concept is about grouping certain function sets (APIs) and "mapping" them to specific DLL files, aiming to achieve abstraction of implementation and maintain compatibility.

API Set DLLs (like `api-ms-win-core-processthreads-l1-1-1.dll` for this case) do not actually possess any functions. These DLLs are for telling the OS which DLL implements a particular function, with the actual function residing in another DLL (in this case, kernel32.dll).

# Conversion Output

This output is generated by IDA 8.3 without symbols (and without gooMBA).

```rust
#[inline(never)]
#[no_mangle]
#[export_name = "nt"]
fn nt() -> u32 {
    let NtGetCurrentProcessorNumber: unsafe extern "system" fn() -> ULONG =
        ri_fn!("NtGetCurrentProcessorNumber");
    return unsafe { NtGetCurrentProcessorNumber() };
}
```

```cpp
__int64 nt()
{
  PPEB_LDR_DATA Ldr; // rax
  struct _LIST_ENTRY *Flink; // r8
  struct _LIST_ENTRY *Blink; // rsi
  int v3; // r10d
  int v4; // r12d
  int v5; // r9d
  struct _LIST_ENTRY *v6; // rbx
  struct _LIST_ENTRY *v7; // rdi
  int v8; // eax
  struct _LIST_ENTRY *v9; // rcx
  unsigned __int8 v10; // r11
  struct _LIST_ENTRY *v11; // r15
  __int64 Blink_high; // rax
  __int64 v13; // r14
  __int64 v14; // rdx
  unsigned int *v15; // r14
  __int64 v16; // rax
  __int64 v17; // r13
  char *v18; // rbp
  __int64 v19; // rcx
  __int64 v20; // rax
  int v21; // r11d
  __int64 v22; // rcx
  char v23; // r12
  unsigned __int8 v24; // r8
  __int64 (*v25)(void); // rdx
  unsigned __int8 v26; // cl
  char *v27; // rax
  char *v28; // rdx
  int v29; // ecx
  unsigned __int8 v30; // r8
  unsigned __int8 v31; // cl
  unsigned __int8 v32; // al
  unsigned __int8 v33; // cl
  unsigned __int8 v34; // r8
  unsigned __int8 v35; // al
  int v37; // [rsp+4h] [rbp-64h]
  struct _LIST_ENTRY *v38; // [rsp+8h] [rbp-60h]
  char v39; // [rsp+10h] [rbp-58h]
  struct _LIST_ENTRY *v40; // [rsp+20h] [rbp-48h]

  Ldr = NtCurrentPeb()->Ldr;
  Flink = Ldr->InLoadOrderModuleList.Flink;
  Blink = Ldr->InLoadOrderModuleList.Blink;
  if ( Flink != Blink )
  {
    v3 = -42511511;
    v39 = 0;
    v4 = 0;
    v5 = 0;
    v38 = Ldr->InLoadOrderModuleList.Blink;
    do
    {
      v6 = Flink[6].Flink;
      v7 = (struct _LIST_ENTRY *)((char *)v6 + ((unsigned __int16)(LODWORD(Flink[5].Blink) - 8) & 0xFFFE));
      v8 = 218083195;
      if ( v6 < v7 )
      {
        v9 = Flink[6].Flink;
        do
        {
          v10 = LOBYTE(v9->Flink) | 0x20;
          if ( (unsigned __int8)(LOBYTE(v9->Flink) - 65) >= 0x1Au )
            v10 = (unsigned __int8)v9->Flink;
          v8 = 16777619 * (v8 ^ v10);
          v9 = (struct _LIST_ENTRY *)((char *)v9 + 2);
        }
        while ( v9 < v7 );
      }
      if ( !v5 || v8 == v5 || v8 && v8 != v4 )
      {
        v11 = Flink[3].Flink;
        Blink_high = SHIDWORD(v11[3].Blink);
        v13 = *(unsigned int *)((char *)&v11[8].Blink + Blink_high);
        if ( *(_DWORD *)((char *)&v11[8].Blink + Blink_high) )
        {
          v40 = Flink;
          v37 = v4;
          v14 = *(unsigned int *)((char *)&v11[1].Blink + v13);
          v15 = (unsigned int *)((char *)v11 + v13);
          v16 = 0i64;
          do
          {
            if ( v16 == v14 )
            {
              Blink = v38;
              v4 = v37;
              Flink = v40;
              goto LABEL_49;
            }
            v17 = v16;
            v18 = (char *)v11 + *(unsigned int *)((char *)&v11->Flink + 4 * v16 + v15[8]);
            v19 = 0i64;
            do
              v20 = v19++;
            while ( v18[v20] );
            v21 = 218083195;
            if ( v19 != 1 )
            {
              v22 = 0i64;
              do
              {
                v23 = v18[v22];
                if ( !v23 )
                  break;
                v24 = v23 | 0x20;
                if ( (unsigned __int8)(v23 - 65) >= 0x1Au )
                  v24 = v18[v22];
                v21 = 16777619 * (v24 ^ v21);
                ++v22;
              }
              while ( v20 != v22 );
            }
            v16 = v17 + 1;
          }
          while ( v21 != v3 );
          v25 = (__int64 (*)(void))((char *)v11
                                  + *(unsigned int *)((char *)&v11->Flink
                                                    + 4
                                                    * *(unsigned __int16 *)((char *)&v11->Flink
                                                                          + 2 * (unsigned int)v17
                                                                          + v15[9])
                                                    + v15[7]));
          v4 = v37;
          if ( (v39 & 1) != 0 )
          {
            Blink = v38;
          }
          else
          {
            v4 = 218083195;
            Blink = v38;
            if ( v6 < v7 )
            {
              v4 = 218083195;
              do
              {
                v26 = LOBYTE(v6->Flink) | 0x20;
                if ( (unsigned __int8)(LOBYTE(v6->Flink) - 65) >= 0x1Au )
                  v26 = (unsigned __int8)v6->Flink;
                v4 = 16777619 * (v4 ^ v26);
                v6 = (struct _LIST_ENTRY *)((char *)v6 + 2);
              }
              while ( v6 < v7 );
            }
          }
          if ( v15 >= (unsigned int *)v25
            || (char *)v15 + *(unsigned int *)((char *)&v11[8].Blink + SHIDWORD(v11[3].Blink) + 4) <= (char *)v25 )
          {
            return v25();
          }
          v27 = (char *)v25 + 1;
          v28 = (char *)v25 + 2;
          v5 = 218083195;
          while ( 1 )
          {
            v29 = (unsigned __int8)*(v27 - 1);
            if ( !*(v27 - 1) )
              goto LABEL_47;
            if ( v29 == 46 )
              break;
            v30 = v29 - 65;
            v31 = v29 | 0x20;
            if ( v30 >= 0x1Au )
              v31 = *(v27 - 1);
            v5 = 16777619 * (v31 ^ v5);
            ++v27;
            ++v28;
          }
          v32 = *v27;
          if ( !v32 )
          {
LABEL_47:
            v3 = 218083195;
            goto LABEL_48;
          }
          v3 = 218083195;
          do
          {
            v33 = v32 - 65;
            v34 = v32;
            v35 = v32 | 0x20;
            if ( v33 >= 0x1Au )
              v35 = v34;
            v3 = 16777619 * (v3 ^ v35);
            v32 = *v28++;
          }
          while ( v32 );
LABEL_48:
          Flink = NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink;
          v39 = 1;
        }
      }
LABEL_49:
      Flink = Flink->Flink;
    }
    while ( Flink != Blink );
  }
  v25 = 0i64;
  return v25();
}
```

# License

[LICENSE - Apache 2.0](./LICENSE)

# Credit

Apache 2.0 - [JustasMasiulis/lazy_importer](https://github.com/JustasMasiulis/lazy_importer)
