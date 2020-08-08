//! Psueudo random number generator based on
//!
/// Reimplementation of https://github.com/eqv/rand_romu
pub struct Rng {
    xstate: u64,
    ystate: u64,
}

impl Rng {
    /// Creates a new RandRumo rng initialized with values from Lehmer64 initialized with `rdtsc`.
    pub fn new() -> Rng {
        // Generate the random state from Lehmer64
        let mut lehmer64 = Lehmer64::new();
        let mut res = Rng {
            xstate: lehmer64.next(),
            ystate: lehmer64.next(),
        };

        // Cycle through to create some chaos
        for _ in 0..100 {
            let _ = res.next();
        }

        res
    }

    pub fn next(&mut self) -> u64 {
        let xp = self.xstate;
        self.xstate = 15241094284759029579u64.wrapping_mul(self.ystate);
        self.ystate = self.ystate.wrapping_sub(xp);
        self.ystate = self.ystate.rotate_left(27);
        return xp;
    }

    /// Returns true 50%  of the time
    pub fn chance_50(&mut self) -> bool {
        self.next() & 0x1 == 0
    }

    /// Returns true 25%  of the time
    pub fn chance_25(&mut self) -> bool {
        self.next() & 0x3 == 0
    }

    /// Returns true 12%  of the time
    pub fn chance_12(&mut self) -> bool {
        self.next() & 0x7 == 0
    }

    /// Returns true 6%  of the time
    pub fn chance_6(&mut self) -> bool {
        self.next() & 0xf == 0
    }

    /// Returns true 3%  of the time
    pub fn chance_3(&mut self) -> bool {
        self.next() & 0x1f == 0
    }

    /// Returns true 3%  of the time
    pub fn chance_1(&mut self) -> bool {
        self.next() & 0x3f == 0
    }

    /// Returns true 75%  of the time
    pub fn chance_75(&mut self) -> bool {
        !self.chance_25()
    }

    /// Returns true 88%  of the time
    pub fn chance_88(&mut self) -> bool {
        !self.chance_12()
    }

    /// Returns true 94%  of the time
    pub fn chance_94(&mut self) -> bool {
        !self.chance_6()
    }

    /// Returns true 97%  of the time
    pub fn chance_97(&mut self) -> bool {
        !self.chance_3()
    }

    /// Returns true 99%  of the time
    pub fn chance_99(&mut self) -> bool {
        !self.chance_1()
    }
}

/// Rng seeded with rdtsc that is generated using Lehmer64
pub struct Lehmer64 {
    value: u128,
}

impl Lehmer64 {
    pub fn new() -> Lehmer64 {
        let mut res = Lehmer64 {
            value: unsafe { core::arch::x86_64::_rdtsc() } as u128,
        };

        // Cycle through to create some chaos
        for _ in 0..100 {
            let _ = res.next();
        }

        res
    }

    pub fn next(&mut self) -> u64 {
        self.value = self.value.wrapping_mul(0xda942042e4dd58b5);
        (self.value >> 64) as u64
    }
}
