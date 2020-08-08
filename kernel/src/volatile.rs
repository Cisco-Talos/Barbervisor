#![cfg_attr(feature = "const_fn", feature(const_fn))]

//! Provides wrapper types `Volatile`, `ReadOnly`, `WriteOnly`, `ReadWrite`, which wrap any copy-able type and allows for
//! volatile memory access to wrapped value. Volatile memory accesses are never optimized away by
//! the compiler, and are useful in many low-level systems programming and concurrent contexts.
//!
//! The wrapper types *do not* enforce any atomicity guarantees; to also get atomicity, consider
//! looking at the `Atomic` wrapper type found in `libcore` or `libstd`.
//!
//! These wrappers do not depend on the standard library and never panic.
//!
//! # Dealing with Volatile Pointers
//!
//! Frequently, one may have to deal with volatile pointers, eg, writes to specific memory
//! locations. The canonical way to solve this is to cast the pointer to a volatile wrapper
//! directly, eg:
//!
//! ```rust
//! use volatile::Volatile;
//!
//! let mut_ptr = 0xFEE00000 as *mut u32;
//!
//! let volatile_ptr = mut_ptr as *mut Volatile<u32>;
//! ```
//!
//! and then perform operations on the pointer as usual in a volatile way. This method works as all
//! of the volatile wrapper types are the same size as their contained values.

use core::ptr;

/// A wrapper type around a volatile variable, which allows for volatile reads and writes
/// to the contained value. The stored type needs to be `Copy`, as volatile reads and writes
/// take and return copies of the value.
///
/// The size of this struct is the same as the size of the contained type.
#[derive(Debug)]
#[repr(transparent)]
pub struct Volatile<T: Copy>(T);

impl<T: Copy> Volatile<T> {
    /// Construct a new volatile instance wrapping the given value.
    ///
    /// ```rust
    /// use volatile::Volatile;
    ///
    /// let value = Volatile::new(0u32);
    /// ```
    ///
    /// # Panics
    ///
    /// This method never panics.
    #[cfg(feature = "const_fn")]
    pub const fn new(value: T) -> Volatile<T> {
        Volatile(value)
    }

    /// Construct a new volatile instance wrapping the given value.
    ///
    /// ```rust
    /// use volatile::Volatile;
    ///
    /// let value = Volatile::new(0u32);
    /// ```
    ///
    /// # Panics
    ///
    /// This method never panics.
    #[cfg(not(feature = "const_fn"))]
    pub fn new(value: T) -> Volatile<T> {
        Volatile(value)
    }

    /// Performs a volatile read of the contained value, returning a copy
    /// of the read value. Volatile reads are guaranteed not to be optimized
    /// away by the compiler, but by themselves do not have atomic ordering
    /// guarantees. To also get atomicity, consider looking at the `Atomic` wrapper type.
    ///
    /// ```rust
    /// use volatile::Volatile;
    ///
    /// let value = Volatile::new(42u32);
    ///
    /// assert_eq!(value.read(), 42u32);
    /// ```
    ///
    /// # Panics
    ///
    /// This method never panics.
    pub fn read(&self) -> T {
        // UNSAFE: Safe, as we know that our internal value exists.
        unsafe { ptr::read_volatile(&self.0) }
    }

    /// Performs a volatile write, setting the contained value to the given value `value`. Volatile
    /// writes are guaranteed to not be optimized away by the compiler, but by themselves do not
    /// have atomic ordering guarantees. To also get atomicity, consider looking at the `Atomic`
    /// wrapper type.
    ///
    /// ```rust
    /// use volatile::Volatile;
    ///
    /// let mut value = Volatile::new(0u32);
    ///
    /// value.write(42u32);
    ///
    /// assert_eq!(value.read(), 42u32);
    /// ```
    ///
    /// # Panics
    ///
    /// This method never panics.
    pub fn write(&mut self, value: T) {
        // UNSAFE: Safe, as we know that our internal value exists.
        unsafe { ptr::write_volatile(&mut self.0, value) };
    }

    /// Performs a volatile read of the contained value, passes a mutable reference to it to the
    /// function `f`, and then performs a volatile write of the (potentially updated) value back to
    /// the contained value.
    ///
    /// ```rust
    /// use volatile::Volatile;
    ///
    /// let mut value = Volatile::new(21u32);
    ///
    /// value.update(|val_ref| *val_ref *= 2);
    ///
    /// assert_eq!(value.read(), 42u32);
    /// ```
    ///
    /// # Panics
    ///
    /// Ths method never panics.
    pub fn update<F>(&mut self, f: F)
    where
        F: FnOnce(&mut T),
    {
        let mut value = self.read();
        f(&mut value);
        self.write(value);
    }
}

impl<T: Copy> Clone for Volatile<T> {
    fn clone(&self) -> Self {
        Volatile(self.read())
    }
}

/// A volatile wrapper which only allows read operations.
///
/// The size of this struct is the same as the contained type.
#[derive(Debug, Clone)]
pub struct ReadOnly<T: Copy>(Volatile<T>);

impl<T: Copy> ReadOnly<T> {
    /// Construct a new read-only volatile wrapper wrapping the given value.
    ///
    /// ```rust
    /// use volatile::ReadOnly;
    ///
    /// let value = ReadOnly::new(42u32);
    /// ```
    ///
    /// # Panics
    ///
    /// This function never panics.
    #[cfg(feature = "const_fn")]
    pub const fn new(value: T) -> ReadOnly<T> {
        ReadOnly(Volatile::new(value))
    }

    /// Construct a new read-only volatile wrapper wrapping the given value.
    ///
    /// ```rust
    /// use volatile::ReadOnly;
    ///
    /// let value = ReadOnly::new(42u32);
    /// ```
    ///
    /// # Panics
    ///
    /// This function never panics.
    #[cfg(not(feature = "const_fn"))]
    pub fn new(value: T) -> ReadOnly<T> {
        ReadOnly(Volatile::new(value))
    }

    /// Perform a volatile read of the contained value, returning a copy of the read value.
    /// Functionally equivalent to `Volatile::read`.
    ///
    /// ```rust
    /// use volatile::ReadOnly;
    ///
    /// let value = ReadOnly::new(42u32);
    /// assert_eq!(value.read(), 42u32);
    /// ```
    ///
    /// # Panics
    ///
    /// This function never panics.
    pub fn read(&self) -> T {
        self.0.read()
    }
}

/// A volatile wrapper which only allows write operations.
///
/// The size of this struct is the same as the contained type.
#[derive(Debug, Clone)]
pub struct WriteOnly<T: Copy>(Volatile<T>);

impl<T: Copy> WriteOnly<T> {
    /// Constructs a new write only volatile wrapper around the given value.
    ///
    /// ```rust
    /// use volatile::WriteOnly;
    ///
    /// let value = WriteOnly::new(0u32);
    /// ```
    ///
    /// # Panics
    ///
    /// This function never panics.
    #[cfg(feature = "const_fn")]
    pub const fn new(value: T) -> WriteOnly<T> {
        WriteOnly(Volatile::new(value))
    }

    /// Constructs a new write only volatile wrapper around the given value.
    ///
    /// ```rust
    /// use volatile::WriteOnly;
    ///
    /// let value = WriteOnly::new(0u32);
    /// ```
    ///
    /// # Panics
    ///
    /// This function never panics.
    #[cfg(not(feature = "const_fn"))]
    pub fn new(value: T) -> WriteOnly<T> {
        WriteOnly(Volatile::new(value))
    }

    /// Performs a volatile write of value `value` into the contained value. Functionally identical
    /// to `Volatile::write`.
    ///
    /// ```rust
    /// use volatile::WriteOnly;
    ///
    /// let mut value = WriteOnly::new(0u32);
    ///
    /// value.write(42u32);
    /// ```
    ///
    /// # Panics
    ///
    /// This method never panics.
    pub fn write(&mut self, value: T) {
        self.0.write(value)
    }
}

/// A volatile wrapper which allows both read and write operations;
/// functionally equivalent to the `Volatile` type, as it is a type
/// alias for it.
///
/// The size of this struct is the same as the contained type.
pub type ReadWrite<T> = Volatile<T>;

#[cfg(test)]
mod tests {
    use super::Volatile;

    #[test]
    fn test_read() {
        assert_eq!(Volatile(42).read(), 42);
    }

    #[test]
    fn test_write() {
        let mut volatile = Volatile(42);
        volatile.write(50);
        assert_eq!(volatile.0, 50);
    }

    #[test]
    fn test_update() {
        let mut volatile = Volatile(42);
        volatile.update(|v| *v += 1);
        assert_eq!(volatile.0, 43);
    }

    #[test]
    fn test_pointer_recast() {
        let mut target_value = 0u32;

        let target_ptr: *mut u32 = &mut target_value;
        let volatile_ptr = target_ptr as *mut Volatile<u32>;

        // UNSAFE: Safe, as we know the value exists on the stack.
        unsafe {
            (*volatile_ptr).write(42u32);
        }

        assert_eq!(target_value, 42u32);
    }
}
