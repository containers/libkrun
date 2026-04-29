extern crate proc_macro;
extern crate quote;
extern crate syn;

use proc_macro::{Literal, TokenStream, TokenTree};
use quote::quote;

#[proc_macro_attribute]
pub fn guest(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut prefix: TokenStream = quote! {
        #[cfg(feature = "guest")]
    }
    .into();

    prefix.extend(input);
    prefix
}

#[proc_macro_attribute]
pub fn host(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut prefix: TokenStream = quote! {
         #[cfg(feature = "host")]
    }
    .into();

    prefix.extend(input);
    prefix
}

/// Compile-time env var with default. Expands to a string literal, usable in `concat!()`.
///
/// ```ignore
/// const X: &str = concat!("prefix ", env_or_default!("MY_VAR", "fallback"), " suffix");
/// ```
#[proc_macro]
pub fn env_or_default(input: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = input.into_iter().collect();

    // Parse: "ENV_VAR_NAME" , "default_value"
    let key = match tokens.first() {
        Some(TokenTree::Literal(lit)) => strip_string_literal(&lit.to_string())
            .unwrap_or_else(|| panic!("first argument must be a string literal")),
        _ => panic!("first argument must be a string literal"),
    };

    match tokens.get(1) {
        Some(TokenTree::Punct(p)) if p.as_char() == ',' => {}
        _ => panic!("expected `,` after first argument"),
    }

    let default_tokens: TokenStream = tokens[2..].iter().cloned().collect();

    match std::env::var(&key) {
        Ok(value) => TokenStream::from(TokenTree::Literal(Literal::string(&value))),
        Err(_) => default_tokens,
    }
}

fn strip_string_literal(s: &str) -> Option<String> {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .map(|s| s.to_owned())
}
