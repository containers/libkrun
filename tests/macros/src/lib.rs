extern crate proc_macro;
extern crate quote;
extern crate syn;

use proc_macro::TokenStream;
use quote::quote;

#[proc_macro_attribute]
pub fn guest(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut prefix: TokenStream = quote! {
        #[cfg(feature = "guest")]
    }
    .into();

    prefix.extend(input);
    prefix.into()
}

#[proc_macro_attribute]
pub fn host(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut prefix: TokenStream = quote! {
         #[cfg(feature = "host")]
    }
    .into();

    prefix.extend(input);
    prefix.into()
}
