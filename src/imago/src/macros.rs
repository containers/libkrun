//! Helper macros.

/// Implements `TryFrom` for enums from their numerical representation.
macro_rules! numerical_enum {
    (
        $(#[$attr:meta])*
        $vis:vis enum $enum_name:ident as $repr:tt {
            $(
                $(#[$id_attr:meta])*
                $identifier:ident = $value:expr,
            )+
        }
    ) => {
        $(#[$attr])*
        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        #[repr($repr)]
        $vis enum $enum_name {
            $(
                $(#[$id_attr])*
                $identifier = $value,
            )+
        }

        impl TryFrom<$repr> for $enum_name {
            type Error = std::io::Error;

            fn try_from(val: $repr) -> std::io::Result<Self> {
                match val {
                    $(x if x == $value => Ok($enum_name::$identifier),)*
                    _ => Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "Invalid value for {}: {:x}",
                                stringify!($enum_name),
                                val,
                            ),
                    )),
                }
            }
        }
    }
}

pub(crate) use numerical_enum;

/// Implements a function as itself.
///
/// For traits that generalize interfaces that duplicate what we have on the struct itself, too.
/// For example, we want to have `IoVectorTrait`, but not export it; requiring users to import that
/// trait just for `.len()` is silly.  So `.len()` is implemented directly on both `IoVector` and
/// `IoVectorMut` -- still, we want to have a generic `IoVectorTrait::len()`, too.  This is what
/// this macro implements.
macro_rules! passthrough_trait_fn {
    { fn $name:ident($($param:ident: $type:ty),*) -> $ret:ty; } => {
        fn $name($($param: $type),*) -> $ret {
            Self::$name($($param),*)
        }
    };

    { fn $name:ident(self$(, $param:ident: $type:ty)*) -> $ret:ty; } => {
        passthrough_trait_fn! { fn $name(self: Self$(, $param: $type)*) -> $ret; }
    };

    { fn $name:ident(&self$(, $param:ident: $type:ty)*) -> $ret:ty; } => {
        passthrough_trait_fn! { fn $name(self: &Self$(, $param: $type)*) -> $ret; }
    };

    { fn $name:ident(&mut self$(, $param:ident: $type:ty)*) -> $ret:ty; } => {
        passthrough_trait_fn! { fn $name(self: &mut Self$(, $param: $type)*) -> $ret; }
    };

    { fn $name:ident(self$(, $param:ident: $type:ty)*); } => {
        passthrough_trait_fn! { fn $name(self$(, $param: $type)*) -> (); }
    };

    { fn $name:ident(&self$(, $param:ident: $type:ty)*); } => {
        passthrough_trait_fn! { fn $name(&self$(, $param: $type)*) -> (); }
    };

    { fn $name:ident(&mut self$(, $param:ident: $type:ty)*); } => {
        passthrough_trait_fn! { fn $name(&mut self$(, $param: $type)*) -> (); }
    };
}

pub(crate) use passthrough_trait_fn;
