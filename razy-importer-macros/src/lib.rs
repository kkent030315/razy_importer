#![crate_type = "rlib"]

#[macro_use]
extern crate const_random;

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use razy_importer::OffsetHashPair;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Expr, LitStr,
};

trait ToTokensSlice {
    fn to_tokens_slice(&self) -> proc_macro2::TokenStream;
}

impl ToTokensSlice for [u8] {
    fn to_tokens_slice(&self) -> proc_macro2::TokenStream {
        let bytes = self.iter().map(|b| quote!(#b));
        return quote!(#(#bytes),*);
    }
}

#[proc_macro]
pub fn ri_khash(input: TokenStream) -> TokenStream {
    let value: Expr = parse_macro_input!(input as Expr);
    let random_u32: u32 = const_random!(u32);
    let mut random_array: [u8; 128] = const_random!([u8; 128]);
    if let Some(last) = random_array.last_mut() {
        *last = 0;
    }
    let s = match &value {
        Expr::Lit(lit_expr) => {
            if let syn::Lit::Str(lit_byte_str) = &lit_expr.lit {
                lit_byte_str
            } else {
                panic!("ri_khash! macro can only be used with string literals.");
            }
        }
        _ => panic!("ri_khash! macro can only be used with string literals."),
    };
    let hash: OffsetHashPair = razy_importer::hash::khash(
        s.value().as_bytes(),
        razy_importer::hash::khash_impl(&random_array, random_u32),
    );
    let expanded: TokenStream = quote! {
        #hash
    }
    .into();
    return expanded;
}

#[proc_macro]
pub fn ri_mod(input: TokenStream) -> TokenStream {
    let module_name: LitStr = parse_macro_input!(input as LitStr);
    let module_name_str: String = module_name.value();
    let expanded: TokenStream = quote! {
        unsafe {
            razy_importer::get_module_base(
                ri_khash!(#module_name_str),
            )
        }
    }
    .into();
    return expanded;
}

struct RiFnMInput {
    function: LitStr,
    module_expr: Expr,
}

impl Parse for RiFnMInput {
    fn parse(input: ParseStream) -> syn::parse::Result<Self> {
        let function: LitStr = input.parse()?;
        let _: syn::token::Comma = input.parse()?;
        let module_expr: Expr = input.parse()?;
        Ok(Self {
            function,
            module_expr,
        })
    }
}

#[proc_macro]
pub fn ri_fn_m(input: TokenStream) -> TokenStream {
    let input_struct: RiFnMInput = parse_macro_input!(input as RiFnMInput);
    let function: LitStr = input_struct.function;
    let module_expr: Expr = input_struct.module_expr;
    let expanded: TokenStream = quote! {
        unsafe {
            std::mem::transmute(razy_importer::get_export(
                #module_expr,
                ri_khash!(#function),
            ))
        }
    }
    .into();
    return expanded;
}

#[proc_macro]
pub fn ri_fn(input: TokenStream) -> TokenStream {
    let function_name: LitStr = parse_macro_input!(input as LitStr);
    let function_name_str: String = function_name.value();
    let expanded: TokenStream = quote! {
        unsafe {
            std::mem::transmute(razy_importer::get_export_forwarded(
                ri_khash!(#function_name_str),
            ))
        }
    }
    .into();
    return expanded;
}
