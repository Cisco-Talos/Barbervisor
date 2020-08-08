# Corpus Generator

Generates a serialized corpus to disk that can be shipped to the kernel.

## Usage

Drop the binary into a directory containing corpus files. Run the binary to generate a `corpgen.corpus` file that can be shipped over to the kernel. The kernel can then deserialize the file to have a `Vec<Vec<u8>>`

## Example

In corpus directory:

```
(ins)$ echo aaa > a
(ins)$ echo bbbbbb > B
(ins)$ echo cccccccccc > c
(ins)$ ./corpgen
"./a" 4
"./B" 7
"./c" 11
Number of files: 3
Largest: 11 -- "./c"
Size of serialized: 54
Corpus written to corpus.corpgen
```

In the kernel:

```rust
let corpus_data = net::get_file("corpgen.corpus");
if corpus_data.len() == 0 { return; }
let corpus = <Vec<Vec<u8>> as Deserialize>::deserialize(&mut corpus_data.as_slice()).unwrap();
```
