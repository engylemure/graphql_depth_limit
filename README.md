# graphql_depth_limit
A graphql depth limit validation in Rust inspired by [graphql_depth_limit](https://github.com/stems/graphql-depth-limit) 

Add this to your `Cargo.toml`:

```toml
[dependencies]
graphql_depth_limit = "0.1.0"
```

and this to your crate root (if you're using Rust 2015):

```rust
extern crate graphql_depth_limit;
```

Here's a simple example for verification of a graphql query:

```rust
use regex::Regex;

fn main() {
    let query = r#"
                query {
                  a {
                    b {
                      c
                    }
                  }
                }
            "#;
    let depth = match QueryDepthAnalyzer::new(query, vec![], |_a, _b| true) {
        Ok(validator) => validator.verify(limit),
        Err(val) => Err(DepthLimitError::Parse(val))
    };
    asssert_eq!(depth.ok()?, 3);
}
```
