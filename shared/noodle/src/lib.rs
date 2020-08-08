#![no_std]
#![allow(unused_macros)]

extern crate core;
extern crate alloc;

#[macro_use] pub mod tuple_match;
#[macro_use] pub mod tuple_gen;

use core::convert::TryInto;
use alloc::borrow::{Cow, ToOwned};
use alloc::vec::Vec;
use alloc::string::String;

/// Serialize a `self` into an existing vector
pub trait Serialize {
    fn serialize(&self, buf: &mut Vec<u8>);
}

/// Deserialize a buffer, creating a Some(`Self`) if the serialization succeeds,
/// otherwise a `None` is returned. `ptr` should be a mutable reference to a
/// slice, this allows the deserializer to "consume" bytes by advancing the
/// pointer. To see how many bytes were deserialized, you can check the
/// difference in the `ptr`'s length before and after the call to deserialize.
///
/// If deserialization fails at any point, all intermediate objects created
/// will be destroyed, and the `ptr` will not be be changed.
///
/// This effectively behaves the same as `std::io::Read`. Since we don't have
/// `std` access in this lib we opt to go this route.
pub trait Deserialize: Sized {
    fn deserialize(ptr: &mut &[u8]) -> Option<Self>;
}

/// Implement `Serialize` trait for types which provide `to_le_bytes()`
macro_rules! serialize_le {
    // Serialize `$input_type` as an `$wire_type` by using `to_le_bytes()`
    // and `from_le_bytes()`. The `$input_type` gets converted to an
    // `$wire_type` via `TryInto`
    ($input_type:ty, $wire_type:ty) => {
        impl Serialize for $input_type {
            fn serialize(&self, buf: &mut Vec<u8>) {
                let wire: $wire_type = (*self).try_into()
                    .expect("Should never happen, input type to wire type");
                buf.extend_from_slice(&wire.to_le_bytes());
            }
        }

        impl Deserialize for $input_type {
            fn deserialize(orig_ptr: &mut &[u8]) -> Option<Self> {
                // Get the slice pointed to by `orig_ptr`
                let ptr: &[u8] = *orig_ptr;

                // Convert the slice to a fixed-size array 
                let arr: [u8; core::mem::size_of::<$wire_type>()] =
                    ptr.get(0..core::mem::size_of::<$wire_type>())?
                        .try_into().ok()?;

                // Convert the array of bytes into the `$wire_type`
                let wire_val = <$wire_type>::from_le_bytes(arr);

                // Try to convert the wire-format type into the desired type
                let converted: $input_type = wire_val.try_into().ok()?;

                // Update the pointer
                *orig_ptr = &ptr[core::mem::size_of::<$wire_type>()..];

                // Return out the deserialized `Self`!
                Some(converted)
            }
        }
    };

    // Serialize an $input_type using `to_le_bytes()` and `from_le_bytes()`
    ($input_type:ty) => {
        serialize_le!($input_type, $input_type);
    };
}

// Implement serialization for all of the primitive types
serialize_le!(u8);
serialize_le!(u16);
serialize_le!(u32);
serialize_le!(u64);
serialize_le!(u128);
serialize_le!(i8);
serialize_le!(i16);
serialize_le!(i32);
serialize_le!(i64);
serialize_le!(i128);
serialize_le!(usize, u64);
serialize_le!(isize, i64);

/// Implement serialize for `&str`
impl Serialize for str {
    fn serialize(&self, buf: &mut Vec<u8>) {
        // Serialize the underlying bytes of the string
        Serialize::serialize(self.as_bytes(), buf);
    }
}

/// Implement serialize for `&str`
impl Serialize for &str {
    fn serialize(&self, buf: &mut Vec<u8>) {
        // Serialize the underlying bytes of the string
        Serialize::serialize(self.as_bytes(), buf);
    }
}

/// Implement serialize for `[T]`
impl<T: Serialize> Serialize for [T] {
    fn serialize(&self, buf: &mut Vec<u8>) {
        // Serialize the number of elements
        Serialize::serialize(&self.len(), buf);

        // Serialize all of the values
        self.iter().for_each(|x| Serialize::serialize(x, buf));
    }
}

/// Implement `Serialize` for `Option`
impl<T: Serialize> Serialize for Option<T> {
    fn serialize(&self, buf: &mut Vec<u8>) {
        if let Some(val) = self.as_ref() {
            // Serialize that this is a some type
            buf.push(1);

            // Serialize the underlying bytes of the value
            Serialize::serialize(val, buf);
        } else {
            // `None` value case
            buf.push(0);
        }
    }
}

/// Implement `Deserialize` for `Option`
impl<T: Deserialize> Deserialize for Option<T> {
    fn deserialize(orig_ptr: &mut &[u8]) -> Option<Self> {
        // Make a copy of the original pointer
        let mut ptr = *orig_ptr;

        // Get if this option is a `Some` value
        let is_some = <u8 as Deserialize>::deserialize(&mut ptr)? != 0;
        
        let ret = if is_some {
            // Deserialize payload
            Some(<T as Deserialize>::deserialize(&mut ptr)?)
        } else {
            None
        };

        // Update the original pointer
        *orig_ptr = ptr;
        Some(ret)
    }
}

/// Implement `Serialize` for `String`
impl Serialize for String {
    fn serialize(&self, buf: &mut Vec<u8>) {
        // Serialize the underlying bytes of the string
        Serialize::serialize(self.as_bytes(), buf);
    }
}

/// Implement `Deserialize` for `String`
impl Deserialize for String {
    fn deserialize(orig_ptr: &mut &[u8]) -> Option<Self> {
        // Make a copy of the original pointer
        let mut ptr = *orig_ptr;

        // Deserialize a vector of bytes
        let vec = <Vec<u8> as Deserialize>::deserialize(&mut ptr)?;

        // Convert it to a string and return it out
        let ret = String::from_utf8(vec).ok()?;

        // Update the original pointer
        *orig_ptr = ptr;
        Some(ret)
    }
}

/// Implement `Serialize` for types which can be `Cow`ed
impl<'a, T: 'a> Serialize for Cow<'a, T>
        where T: Serialize + ToOwned + ?Sized {
    fn serialize(&self, buf: &mut Vec<u8>) {
        Serialize::serialize(self.as_ref(), buf);
    }
}

/// Implement `Deserialize` for types which can be `Cow`ed
impl<'a, T: 'a> Deserialize for Cow<'a, T>
        where T: ToOwned + ?Sized,
              <T as ToOwned>::Owned: Deserialize,
              Cow<'a, T>: From<<T as ToOwned>::Owned> {
    fn deserialize(orig_ptr: &mut &[u8]) -> Option<Self> {
        // Make a copy of the original pointer
        let mut ptr = *orig_ptr;

        // Deserialize into the owned type for the `Cow`
        let ret =
            <<T as ToOwned>::Owned as Deserialize>::deserialize(&mut ptr)?;

        // Update the original pointer
        *orig_ptr = ptr;
        Some(Cow::from(ret))
    }
}

/// Implement `Serialize` for `Vec<T>`
impl<T: Serialize> Serialize for Vec<T> {
    fn serialize(&self, buf: &mut Vec<u8>) {
        // Serialize the number of elements
        Serialize::serialize(&self.len(), buf);

        // Serialize all of the values
        self.iter().for_each(|x| Serialize::serialize(x, buf));
    }
}

/// Implement `Deserialize` for `Vec`s that contain all `Deserialize` types
impl<T: Deserialize> Deserialize for Vec<T> {
    fn deserialize(orig_ptr: &mut &[u8]) -> Option<Self> {
        // Make a copy of the original pointer
        let mut ptr = *orig_ptr;

        // Get the length of the vector in elements
        let len = <usize as Deserialize>::deserialize(&mut ptr)?;

        // Allocate the vector we're going to return
        let mut vec = Vec::with_capacity(len);

        // Deserialize all the components
        for _ in 0..len {
            vec.push(<T as Deserialize>::deserialize(&mut ptr)?);
        }

        // Update original pointer and return out the deserialized vector
        *orig_ptr = ptr;
        Some(vec)
    }
}

/// Implement `Serialize` trait for arrays of types which implement `Serialize`
macro_rules! serialize_arr {
    ($arrsize:expr, $($foo:expr),*) => {
        impl<T: Serialize> Serialize for [T; $arrsize] {
            fn serialize(&self, buf: &mut Vec<u8>) {
                // Serialize all of the values
                self.iter().for_each(|x| Serialize::serialize(x, buf));
            }
        }

        impl<T: Deserialize> Deserialize for [T; $arrsize] {
            fn deserialize(orig_ptr: &mut &[u8]) -> Option<Self> {
                // Make a copy of the original pointer
                let mut _ptr = *orig_ptr;

                // Deserialize the array
                let arr = [$(
                    {let _ = $foo; Deserialize::deserialize(&mut _ptr)?},
                )*];

                // Update the original pointer and return out the array
                *orig_ptr = _ptr;
                Some(arr)
            }
        }
    }
}

// Implement serialization and deserialization for all arrays of types which
// are serializable and/or deserialiable up to fixed-width 32 entry arrays
serialize_arr!( 0,);
serialize_arr!( 1, 0);
serialize_arr!( 2, 0, 0);
serialize_arr!( 3, 0, 0, 0);
serialize_arr!( 4, 0, 0, 0, 0);
serialize_arr!( 5, 0, 0, 0, 0, 0);
serialize_arr!( 6, 0, 0, 0, 0, 0, 0);
serialize_arr!( 7, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!( 8, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!( 9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
serialize_arr!(32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

/// Implement serialize and deserialize on an enum or structure definition.
/// 
/// This is used by just wrapping a structure definition like:
///
/// `noodle!(serialize, deserialize, struct Foo { bar: u32 })`
///
/// This can be used on any structure or enum definition and automatically
/// implements the serialize and deserialize traits for it by enumerating every
/// field in the structure (or enum variant) and serializing it out in
/// definition order.
///
/// This all looks really complicated, but it's really just a lot of copied
/// and pasted code that can represent a structure or enum shape in macros.
/// These macros destruct all possible structs and enums and gives us "access"
/// to the inner field names, ordering, and types. This allows us to invoke
/// the `serialize` or `deserialize` routines for every member of the
/// structure. It's that simple!
#[macro_export]
macro_rules! noodle {
    // Create a new struct with serialize and deserialize implemented
    (serialize, deserialize,
        $(#[$attr:meta])* $vis:vis struct $structname:ident
            // Named struct
            $({
                $(
                    $(#[$named_attr:meta])*
                        $named_vis:vis $named_field:ident: $named_type:ty
                ),*$(,)?
            })?

            // Named tuple
            $((
                $(
                    $(#[$tuple_meta:meta])* $tuple_vis:vis $tuple_typ:ty
                ),*$(,)? 
            );)?

            // Eat semicolons
            $(;)?
    ) => {
        noodle!(define_struct,
            $(#[$attr])* $vis struct $structname
            // Named struct
            $({
                $(
                    $(#[$named_attr])*
                        $named_vis $named_field: $named_type
                ),*
            })?

            // Named tuple
            $((
                $(
                    $(#[$tuple_meta])* $tuple_vis $tuple_typ
                ),*
            );)?
        );
        noodle!(impl_serialize_struct,
            $(#[$attr])* $vis struct $structname
            // Named struct
            $({
                $(
                    $(#[$named_attr])*
                        $named_vis $named_field: $named_type
                ),*
            })?

            // Named tuple
            $((
                $(
                    $(#[$tuple_meta])* $tuple_vis $tuple_typ
                ),*
            );)?
        );
        noodle!(impl_deserialize_struct,
            $(#[$attr])* $vis struct $structname
            // Named struct
            $({
                $(
                    $(#[$named_attr])*
                        $named_vis $named_field: $named_type
                ),*
            })?

            // Named tuple
            $((
                $(
                    $(#[$tuple_meta])* $tuple_vis $tuple_typ
                ),*
            );)?
        );
    };

    // Define an empty structure
    (define_struct,
        $(#[$attr:meta])* $vis:vis struct $structname:ident
    ) => {
        $(#[$attr])* $vis struct $structname;
    };

    // Define a structure
    (define_struct,
        $(#[$attr:meta])* $vis:vis struct $structname:ident
            // Named struct
            $({
                $(
                    $(#[$named_attr:meta])*
                        $named_vis:vis $named_field:ident: $named_type:ty
                ),*$(,)?
            })?

            // Named tuple
            $((
                $(
                    $(#[$tuple_meta:meta])* $tuple_vis:vis $tuple_typ:ty
                ),*$(,)? 
            );)?
    ) => {
        $(#[$attr])* $vis struct $structname
        // Named struct
        $({
            $(
                $(#[$named_attr])*
                    $named_vis $named_field: $named_type
            ),*
        })?

        // Named tuple
        $((
            $(
                $(#[$tuple_meta])* $tuple_vis $tuple_typ
            ),*
        );)?
    };

    // Implement serialization for a structure
    (impl_serialize_struct,
        $(#[$attr:meta])* $vis:vis struct $structname:ident
            // Named struct
            $({
                $(
                    $(#[$named_attr:meta])*
                        $named_vis:vis $named_field:ident: $named_type:ty
                ),*$(,)?
            })?

            // Named tuple
            $((
                $(
                    $(#[$tuple_meta:meta])* $tuple_vis:vis $tuple_typ:ty
                ),*$(,)? 
            );)?
    ) => {
        impl Serialize for $structname {
            fn serialize(&self, buf: &mut Vec<u8>) {
                // Named struct
                $(
                    $(
                        Serialize::serialize(&self.$named_field, buf);
                    )*
                )?

                // Named tuple
                handle_serialize_named_tuple!(
                    self, buf $($(, $tuple_typ)*)?);
            }
        }
    };

    // Implement deserialization for a field-less structs
    (impl_deserialize_struct,
        $(#[$attr:meta])* $vis:vis struct $structname:ident
    ) => {
        impl Deserialize for $structname {
            fn deserialize(orig_ptr: &mut &[u8]) -> Option<Self> {
                Some($structname)
            }
        }
    };

    // Implement deserialization for a structure
    (impl_deserialize_struct,
        $(#[$attr:meta])* $vis:vis struct $structname:ident
            // Named struct
            $({
                $(
                    $(#[$named_attr:meta])*
                        $named_vis:vis $named_field:ident: $named_type:ty
                ),*$(,)?
            })?

            // Named tuple
            $((
                $(
                    $(#[$tuple_meta:meta])* $tuple_vis:vis $tuple_typ:ty
                ),*$(,)? 
            );)?
    ) => {
        impl Deserialize for $structname {
            fn deserialize(orig_ptr: &mut &[u8]) -> Option<Self> {
                // Get the original pointer
                let mut ptr = *orig_ptr;

                // Named struct
                $(if true {
                    
                    let ret = $structname {
                        $(
                            $named_field: Deserialize::deserialize(&mut ptr)?,
                        )*
                    };

                    // Update the original pointer
                    *orig_ptr = ptr;

                    return Some(ret);
                })?

                // Named tuple
                $(if true {
                    let ret = $structname(
                        $(
                            <$tuple_typ as Deserialize>::
                                deserialize(&mut ptr)?,
                        )*
                    );

                    // Update the original pointer
                    *orig_ptr = ptr;

                    return Some(ret);
                })?

                // Not reachable
                unreachable!("How'd you get here?");
            }
        }
    };

    // Create a new enum with serialize and deserialize implemented
    (serialize, deserialize,
        $(#[$attr:meta])* $vis:vis enum $enumname:ident {
            // Go through each variant in the enum
            $(
                // Variant attributes
                $(#[$variant_attr:meta])*

                // Identifier for the enum variant, always present
                $variant_ident:ident
                
                // An enum item struct
                $({
                    $(
                        $(#[$named_attr:meta])*
                            $named_field:ident: $named_type:ty
                    ),*$(,)?
                })?

                // An enum item tuple
                $((
                    $(
                        $(#[$tuple_meta:meta])* $tuple_typ:ty
                    ),*$(,)? 
                ))?

                // An enum discriminant
                $(= $expr:expr)?
            ),*$(,)?
        }
    ) => {
        noodle!(define_enum,
            $(#[$attr])* $vis enum $enumname {
                // Go through each variant in the enum
                $(
                    // Variant attributes
                    $(#[$variant_attr])*

                    // Identifier for the enum variant, always present
                    $variant_ident
                    
                    // An enum item struct
                    $({
                        $(
                            $(#[$named_attr])* $named_field: $named_type
                        ),*
                    })?

                    // An enum item tuple
                    $((
                        $(
                            $(#[$tuple_meta])* $tuple_typ
                        ),*
                    ))?

                    // An enum discriminant
                    $(= $expr)?
                ),*
            });
        noodle!(impl_serialize_enum,
            $(#[$attr])* $vis enum $enumname {
                // Go through each variant in the enum
                $(
                    // Variant attributes
                    $(#[$variant_attr])*

                    // Identifier for the enum variant, always present
                    $variant_ident
                    
                    // An enum item struct
                    $({
                        $(
                            $(#[$named_attr])* $named_field: $named_type
                        ),*
                    })?

                    // An enum item tuple
                    $((
                        $(
                            $(#[$tuple_meta])* $tuple_typ
                        ),*
                    ))?

                    // An enum discriminant
                    $(= $expr)?
                ),*
            });
        noodle!(impl_deserialize_enum,
            $(#[$attr])* $vis enum $enumname {
                // Go through each variant in the enum
                $(
                    // Variant attributes
                    $(#[$variant_attr])*

                    // Identifier for the enum variant, always present
                    $variant_ident
                    
                    // An enum item struct
                    $({
                        $(
                            $(#[$named_attr])* $named_field: $named_type
                        ),*
                    })?

                    // An enum item tuple
                    $((
                        $(
                            $(#[$tuple_meta])* $tuple_typ
                        ),*
                    ))?

                    // An enum discriminant
                    $(= $expr)?
                ),*
            });
    };

    (define_enum,
        $(#[$attr:meta])* $vis:vis enum $enumname:ident {
            // Go through each variant in the enum
            $(
                // Variant attributes
                $(#[$variant_attr:meta])*

                // Identifier for the enum variant, always present
                $variant_ident:ident
                
                // An enum item struct
                $({
                    $(
                        $(#[$named_attr:meta])*
                            $named_field:ident: $named_type:ty
                    ),*$(,)?
                })?

                // An enum item tuple
                $((
                    $(
                        $(#[$tuple_meta:meta])* $tuple_typ:ty
                    ),*$(,)? 
                ))?

                // An enum discriminant
                $(= $expr:expr)?
            ),*$(,)?
        }) => {
            // Just define the enum as is
            $(#[$attr])* $vis enum $enumname {
                // Go through each variant in the enum
                $(
                    // Variant attributes
                    $(#[$variant_attr])*

                    // Identifier for the enum variant, always present
                    $variant_ident
                    
                    // An enum item struct
                    $({
                        $(
                            $(#[$named_attr])* $named_field: $named_type
                        ),*
                    })?

                    // An enum item tuple
                    $((
                        $(
                            $(#[$tuple_meta])* $tuple_typ
                        ),*
                    ))?

                    // An enum discriminant
                    $(= $expr)?
                ),*
            }
    };

    (impl_serialize_enum,
        $(#[$attr:meta])* $vis:vis enum $enumname:ident {
            // Go through each variant in the enum
            $(
                // Variant attributes
                $(#[$variant_attr:meta])*

                // Identifier for the enum variant, always present
                $variant_ident:ident
                
                // An enum item struct
                $({
                    $(
                        $(#[$named_attr:meta])*
                            $named_field:ident: $named_type:ty
                    ),*$(,)?
                })?

                // An enum item tuple
                $((
                    $(
                        $(#[$tuple_meta:meta])* $tuple_typ:ty
                    ),*$(,)? 
                ))?

                // An enum discriminant
                $(= $expr:expr)?
            ),*$(,)?
        }) => {
        impl Serialize for $enumname {
            fn serialize(&self, buf: &mut Vec<u8>) {
                let mut _count = 0u32;

                // Go through each variant
                $(
                    handle_serialize_enum_variants!(
                        self, $enumname, $variant_ident, buf, &_count,
                        $({$($named_field),*})? $(($($tuple_typ),*))?);

                    _count += 1;
                )*
            }
        }
    };

    (impl_deserialize_enum,
        $(#[$attr:meta])* $vis:vis enum $enumname:ident {
            // Go through each variant in the enum
            $(
                // Variant attributes
                $(#[$variant_attr:meta])*

                // Identifier for the enum variant, always present
                $variant_ident:ident
                
                // An enum item struct
                $({
                    $(
                        $(#[$named_attr:meta])*
                            $named_field:ident: $named_type:ty
                    ),*$(,)?
                })?

                // An enum item tuple
                $((
                    $(
                        $(#[$tuple_meta:meta])* $tuple_typ:ty
                    ),*$(,)? 
                ))?

                // An enum discriminant
                $(= $expr:expr)?
            ),*$(,)?
        }) => {
        impl Deserialize for $enumname {
            fn deserialize(orig_ptr: &mut &[u8]) -> Option<Self> {
                // Get the original pointer
                let mut ptr = *orig_ptr;

                // Count tracking enum variants
                let mut _count = 0u32;

                // Get the enum variant
                let variant = u32::deserialize(&mut ptr)?;

                // Go through each variant
                $(
                    handle_deserialize_enum_variants!(
                        variant, $enumname, $variant_ident,
                        orig_ptr, ptr, _count,
                        $({$($named_field),*})? $(($($tuple_typ),*))?);

                    _count += 1;
                )*

                // Failed to find a matching variant, return `None`
                None
            }
        }
    };
}

/// Handles serializing of the 3 different enum variant types. Enum struct
/// variants, enum tuple variants, and enum discriminant/bare variants
#[macro_export]
macro_rules! handle_serialize_enum_variants {
    // Named enum variants
    ($self:ident, $enumname:ident, $variant_ident:ident,
            $buf:expr, $count:expr, {$($named_field:ident),*}) => {
        if let $enumname::$variant_ident { $($named_field),* } = $self {
            // Serialize the variant ID
            Serialize::serialize($count, $buf);

            // Serialize all fields
            $(
                Serialize::serialize($named_field, $buf);
            )*
        }
    };

    // Tuple enum variants
    ($self:ident, $enumname:ident, $variant_ident:ident,
            $buf:expr, $count:expr, ($($tuple_typ:ty),*)) => {
        handle_serialize_tuple_match!($self, $count, $buf, $enumname,
            $variant_ident $(, $tuple_typ)*);
    };

    // Discriminant or empty enum variants
    ($self:ident, $enumname:ident, $variant_ident:ident,
            $buf:expr, $count:expr,) => {
        if let $enumname::$variant_ident = $self {
            // Serialize the variant ID
            Serialize::serialize($count, $buf);
        }
    };
}

/// Handles deserializing of the 3 different enum variant types. Enum struct
/// variants, enum tuple variants, and enum discriminant/bare variants
#[macro_export]
macro_rules! handle_deserialize_enum_variants {
    // Named enum variants
    ($variant:ident, $enumname:ident, $variant_ident:ident, $orig_ptr:expr,
            $buf:expr, $count:expr, {$($named_field:ident),*}) => {
        if $count == $variant {
            // Construct the enum
            let ret = $enumname::$variant_ident {
                $(
                    $named_field: Deserialize::deserialize(&mut $buf)?,
                )*
            };

            // Update the original pointer
            *$orig_ptr = $buf;

            return Some(ret);
        }
    };

    // Tuple enum variants
    ($variant:ident, $enumname:ident, $variant_ident:ident, $orig_ptr:expr,
            $buf:expr, $count:expr, ($($tuple_typ:ty),*)) => {
        if $count == $variant {
            // Construct the enum
            let ret = $enumname::$variant_ident (
                $(
                    <$tuple_typ as Deserialize>::deserialize(&mut $buf)?,
                )*
            );

            // Update the original pointer
            *$orig_ptr = $buf;

            return Some(ret);
        }
    };

    // Discriminant or empty enum variants
    ($variant:ident, $enumname:ident, $variant_ident:ident, $orig_ptr:expr,
            $buf:expr, $count:expr,) => {
        if $count == $variant {
            // Construct the enum
            let ret = $enumname::$variant_ident;

            // Update the original pointer
            *$orig_ptr = $buf;

            return Some(ret);
        }
    };
}

#[cfg(test)]
mod test {
    #![allow(unused)]
    
    use crate::*;

    // Serialize a payload and then validate that when it is deserialized it
    // matches the serialized payload identically
    macro_rules! test_serdes {
        ($payload_ty:ty, $payload:expr) => {
            // Allocate serialization buffer
            let mut buf = Vec::new();

            // Serialize `payload`
            $payload.serialize(&mut buf);

            // Allocate a pointer to the serialized buffer
            let mut ptr = &buf[..];

            // Deserialize the payload
            let deser_payload = <$payload_ty>::deserialize(&mut ptr)
                .expect("Failed to deserialize payload");

            // Make sure all bytes were consumed from the serialized buffer
            assert!(ptr.len() == 0,
                "Deserialization did not consume all serialized bytes");

            // Make sure the original payload and the deserialized payload
            // match
            assert!($payload == deser_payload,
                "Serialization and deserialization did not match original");
        }
    }

    #[test]
    fn test_enums() {
        // Not constructable, but we should handle this empty enum case
        noodle!(serialize, deserialize,
            enum TestA {}
        );

        // Basic enum
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            enum TestB {
                Apples,
                Bananas,
            }
        );
        test_serdes!(TestB, TestB::Apples);
        test_serdes!(TestB, TestB::Bananas);

        // Enum with a discriminant
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            enum TestC {
                Apples = 6,
                Bananas
            }
        );
        test_serdes!(TestC, TestC::Apples);
        test_serdes!(TestC, TestC::Bananas);

        // Enum with all types of variants, and some extra attributes at each
        // level to test attribute handling
        noodle!(serialize, deserialize,
            /// Big doc comment here
            /// with many lines
            /// you know?
            #[derive(PartialEq)]
            enum TestD {
                #[cfg(test)]
                Apples {},
                Cars,
                Bananas {
                    /* comment
                     */
                    #[cfg(test)]
                    x: u32,
                    /// doc comment
                    z: i32
                },
                // Another comment
                Cake(),
                Weird(,),
                Cakes(u32),
                Foopie(i8, i32,),
                Testing(i128, i64),
                Arrayz([u8; 4]),
                Lotsotuple(i8,i8,i8,i8,i8,i8,i8,i8,i8,i8,i8,i8,i8,i8,i8,i8),
            }
        );
        test_serdes!(TestD, TestD::Apples {});
        test_serdes!(TestD, TestD::Cars);
        test_serdes!(TestD, TestD::Bananas { x: 932923, z: -348192 });
        test_serdes!(TestD, TestD::Cake());
        test_serdes!(TestD, TestD::Weird());
        test_serdes!(TestD, TestD::Cakes(0x13371337));
        test_serdes!(TestD, TestD::Foopie(-9, 19));
        test_serdes!(TestD, TestD::Testing(0xc0c0c0c0c0c0c0c0c0c0c0, -10000));
        test_serdes!(TestD, TestD::Arrayz([9; 4]));
        test_serdes!(TestD, TestD::Lotsotuple(0,0,0,0,0,5,0,0,0,0,0,0,0,9,0,0));
    }

    #[test]
    fn test_struct() {
        // Empty struct
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestA {}
        );
        test_serdes!(TestA, TestA {});

        // Standard struct
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestB {
                foo: u32,
                bar: i32,
            }
        );
        test_serdes!(TestB, TestB { foo: 4343, bar: -234 });

        // Standard struct with some arrays
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestC {
                foo: u32,
                pub bar: [u32; 8],
            }
        );
        test_serdes!(TestC, TestC { foo: 4343, bar: [10; 8] });

        // Bare struct
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestD;
        );
        test_serdes!(TestD, TestD);
        
        // Empty named tuple
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestE();
        );
        test_serdes!(TestE, TestE());

        // Named tuple
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestF(u32, i128);
        );
        test_serdes!(TestF, TestF(!0, -42934822412));

        // Named tuple with trailing comma
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestG(u32, i128,);
        );
        test_serdes!(TestG, TestG(4, 6));

        // Named tuple with array and nested structure
        noodle!(serialize, deserialize,
            #[derive(PartialEq)]
            struct TestH(u32, [i8; 4], TestG);
        );
        test_serdes!(TestH, TestH(99, [3; 4], TestG(5, -23)));
    }
}

