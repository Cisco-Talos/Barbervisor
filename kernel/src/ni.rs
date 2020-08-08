//! Naive implementation of ni.c: mini-radamsa written in C
use alloc::str;
use crate::Rng;
use alloc::vec::Vec;
use alloc::borrow::ToOwned;
use spin::Mutex;

const AIMROUNDS: usize = 32;
const AIMAX: usize = 256;
const AIMLEN: usize = 512;
const BUFSIZE: usize = 32886;

lazy_static! {
    static ref RNG: Mutex<Rng> = Mutex::new(Rng::new());
}

/// Wrapper around `rdrand` instruction to generate a random number
fn rdrand() -> usize {
    /*
    let ret: u64;
    unsafe {llvm_asm!("rdrand $0" : "=r"(ret)) }
    ret as usize
    */
    RNG.lock().next() as usize
}

/// Generate a random u8 leveraging `rdrand`
fn rand_u8() -> u8 {
    (rdrand() % 255) as u8
}

/// Generate a random number [0; end)
fn random(end: usize) -> usize {
    if end == 0 {
        return 0;
    }

    rdrand() % end
}

/// Generate two random numbers that are not the same
/// returns two numbers, the first is less than the second
fn two_rand_numbers(len: usize) -> (usize, usize) {
    let mut a = rdrand() % len;
    let mut b = rdrand() % len;
    if len == 1 {
        return (0, 1);
    }

    loop {
        if a != b {
            break;
        }
        a = rdrand() % len;
        b = rdrand() % len;
    }

    if a > b {
        (b, a)
    } else {
        (a, b)
    }
}

fn sufscore(a: &[u8], b: &[u8]) -> usize {
    let mut last = 255;
    let mut n = 0;
    for (a_char, b_char) in a.iter().zip(b.iter()) {
        if n < AIMAX {
            break;
        }

        if a_char == b_char {
            break;
        }

        if *a_char != last {
            last = *a_char;
            n += 32;
        }
    }

    n
}

fn aim(from: &[u8], to: &[u8], jump: &mut usize, land: &mut usize) {
    let fend = from.len();
    let tend = to.len();
    let mut best_score = 0;
    let mut score;
    if fend == 0 {
        *jump = 0;
        *land = random(tend);
        return;
    }

    if tend == 0 {
        *land = 0;
        return;
    }

    *jump = random(fend);
    *land = random(tend);

    let rounds = random(AIMROUNDS);
    for _ in 0..rounds {
        let mut maxs = AIMLEN;
        let j = random(fend);
        let mut l = random(tend);
        while maxs > 0 && l < tend && from.iter().take(j).next() != to.iter().take(l).next() {
            l += 1;
            maxs -= 1;
        }

        score = sufscore(&from[j..], &to[l..]);
        if score > best_score {
            best_score = score;
            *jump = j;
            *land = l;
        }
    }
}

/// Generate a random substring from one of the given corpus samples
fn random_block<'a>(data: Vec<u8>, samples: &Vec<Vec<u8>>) -> Vec<u8> {
    let rand_index = random(samples.len());
    let rand_sample = &samples[rand_index];
    if rand_sample.len() < 3 {
        return data;
    }

    let start = random(rand_sample.len() - 2);
    let mut len = rand_sample.len() - start;
    if len > 4 * data.len() {
        len = 4 * data.len();
    }
    len = random(len);
    rand_sample[len..].to_vec()
}

/// Returns the start and end indeces of a random number in the buffer
fn seek_num(data: &[u8]) -> Option<(usize, usize)> {
    let end = data.len();
    let rand_start = random(end);
    let mut start_index = None;
    let mut end_index = None;
    for (i, c) in data[rand_start..].iter().enumerate() {
        match (*c as char, start_index) {
            // First time seeing a number
            ('0'..'9', None) => start_index = Some(i + rand_start),

            // Still seeing a number, continue
            ('0'..'9', Some(_)) => continue,

            // Saw some number, and are no longer seeing digits
            (_, Some(_)) => {
                end_index = Some(i + rand_start);
                break;
            }

            // Everything else
            _ => continue,
        }
    }

    if let (Some(start), Some(end)) = (start_index, end_index) {
        // If found both start and end, deconstruct to a single Option
        Some((start, end))
    } else {
        // No number found
        None
    }
}

/// Randomly changes or bit flips a number
fn twiddle(val: i64) -> i64 {
    let mut result = val;
    loop {
        match random(3) {
            // Make a new random i64 number
            0 => result = random(i64::max_value() as usize) as i64,
            // Flip one of the result bits
            1 => result ^= 1 << random(64 - 1),
            // Add a number relatively close to 0
            2 => result += random(5) as i64 - 2,
            _ => continue,
        }

        // Continue twiddling 50% of the time
        if rdrand() & 1 == 0 {
            break;
        }
    }
    result
}

/// Returns the position and found delimiter in an input buffer
fn drange_start(data: &[u8]) -> Option<(usize, &u8)> {
    data.iter()
        .enumerate()
        .filter(|&(_, c)| match *c as char {
            '[' | '<' | '(' | '\n' => true,
            _ => false,
        })
        .next()
        .clone()
}

/// Return the opposite deliminator for a given deliminator
fn other_delim(delim: u8) -> Option<u8> {
    match delim as char {
        '<' => Some('>' as u8),
        '(' => Some(')' as u8),
        '{' => Some('}' as u8),
        '[' => Some(']' as u8),
        '>' => Some('<' as u8),
        ')' => Some('(' as u8),
        '}' => Some('{' as u8),
        ']' => Some('[' as u8),
        '\n' => Some('\n' as u8),
        _ => unimplemented!(),
    }
}

/// Returns the position of the ending of the delimited string
///
/// # Example
///
/// ```
/// let data = "<test><SUPERINNER!/></test>";
/// let res = ni_rs::drange_end(&data, '>').unwrap();
/// assert!(&data[..res] == "<test>" ||
///         &data[..res] == "<test><SUPERINNER!/>" ||
///         &data[..res] == "<test><SUPERINNER!/></test>");
///
/// let data = "Example HTML - not here";
/// let res = ni_rs::drange_end(&data[13..], '>');
/// assert_eq!(res, None);
/// ```
fn drange_end(data: &[u8], delim_close: u8) -> Option<usize> {
    let delim_open = other_delim(delim_close)?;

    let mut depth = 0;
    for (i, c) in data.iter().enumerate() {
        if *c == delim_close {
            depth -= 1;
            if depth == 0 {
                if rdrand() & 3 == 0 {
                    return Some(i + 1);
                }

                let next = drange_end(&data[i + 1..], delim_close);
                match next {
                    Some(x) => return Some(i + 1 + x),
                    None => return Some(i + 1),
                }
            }
        } else if *c == delim_open {
            depth += 1;
        } else if c & 128 > 0 {
            return None;
        }
    }

    return None;
}

/// Returns the first found delimited string in a given buffer
///
/// # Example
///
/// ```
/// let data = "Example HTML <test></test>";
/// let (start, end) = ni_rs::drange(data).unwrap();
/// assert!(&data[start..end] == "<test>" ||
///         &data[start..end] == "<test></test>");
///
///
/// let data = "Example HTML - not here";
/// let res = ni_rs::drange(data);
/// assert_eq!(res, None);
/// ```
fn drange(data: &[u8]) -> Option<(usize, usize)> {
    let (delim_start, delim_char) = drange_start(data)?;
    let wanted_delim = other_delim(*delim_char)?;

    let delim_end = drange_end(&data[delim_start..], wanted_delim)?;

    // delim_end is the offset from the start of the delimited string
    // need to add the start offset to get the correct index
    //
    // +1 to include the last character so we can do
    // data[delim_start..delim_end]
    return Some((delim_start, delim_start + delim_end));
}

/// Attempts to find another delimited string elsewhere in the input buffer
///
/// # Example
///
/// ```
/// let data = "<test><SUPERINNER!/></test><h>";
/// let (start, end) = ni_rs::other_drange(&data, '<').unwrap();
/// assert!(&data[start..end] == "<test>" ||
///         &data[start..end] == "<test><SUPERINNER!/>" ||
///         &data[start..end] == "<test><SUPERINNER!/></test>" ||
///         &data[start..end] == "<test><SUPERINNER!/></test><h>" ||
///         &data[start..end] == "<SUPERINNER!/>" ||
///         &data[start..end] == "<SUPERINNER!/></test>" ||
///         &data[start..end] == "<SUPERINNER!/></test><h>" ||
///         &data[start..end] == "</test>" ||
///         &data[start..end] == "</test><h>" ||
///         &data[start..end] == "<h>");
/// ```
fn other_drange(data: &[u8], delim_start: u8) -> Option<(usize, usize)> {
    let delim_close = other_delim(delim_start)?;

    for _ in 0..32 {
        let start = random(data.len());
        let temp_data = &data[start..];
        for (i, c) in temp_data.iter().enumerate() {
            if *c == delim_start {
                let delim_end = drange_end(&temp_data[i..], delim_close);
                match delim_end {
                    None => continue,
                    Some(end) => {
                        return Some((start + i, start + i + end));
                    }
                }
            }
        }
    }

    None
}

// fn mutate_area<W: Write>(data: &[u8], samples: &Vec<Vec<u8>>, output: &mut W) {
fn mutate_area(data: &[u8], samples: &Vec<Vec<u8>>, output: &mut Vec<u8>) {
    let end = data.len();
    loop {
        let r = rdrand() % 35;
        // println!("mutate_area r: {}", r);
        match r {
            // match 7 {
            0 => {
                // Insert a random byte
                let position = random(end);
                output.extend_from_slice(&data[..position]);
                output.extend_from_slice(&[rand_u8()]);
                output.extend_from_slice(&data[position..]);
                return;
            }
            1 => {
                // Delete a random byte
                let position = random(end);
                if position + 1 >= end {
                    continue;
                }
                output.extend_from_slice(&data[..position]);
                output.extend_from_slice(&data[position + 1..]);
                return;
            }
            2..4 => {
                // Jump / Overlapping sequences
                if end <= 1 {
                    continue;
                }

                // Generate two random numbers where a < b
                let (a, b) = two_rand_numbers(end);
                output.extend_from_slice(&data[..a]);
                output.extend_from_slice(&data[b..]);
                return;
            }
            4..6 => {
                // Repeat characters
                if end < 2 {
                    continue;
                }

                let mut n = 8;
                while rdrand() & 1 == 0 && n < 20000 {
                    n <<= 1;
                }

                n = rdrand() % n + 2;

                // Generate two random numbers where a < b
                let (s, e) = two_rand_numbers(end);
                let mut len = e - s;

                output.extend_from_slice(&data[..s]);

                if len * n > 0x8000000 {
                    len = rdrand() % 1024 + 2;
                }

                // Insert some substring `n` times
                for _ in 0..n {
                    output.extend_from_slice(&data[s..s + len]);
                }

                // Write the rest of the string
                output.extend_from_slice(&data[s..]);
                return;
            }
            6 => {
                // Insert random data
                let position = random(end);
                let n = rdrand() % 1022 + 2;
                output.extend_from_slice(&data[..position]);
                for _ in 0..n {
                    output.extend_from_slice(&[rand_u8()]);
                }
                output.extend_from_slice(&data[position..]);
                return;
            }
            7..13 => {
                // Aimed jump to self
                if end < 5 {
                    continue;
                }

                let mut j = 0;
                let mut l = 0;
                aim(data, data, &mut j, &mut l);

                output.extend_from_slice(&data[..j]);
                output.extend_from_slice(&data[l..]);
                return;
            }
            13..22 => {
                // Aimed random block fusion
                if end < 8 {
                    continue;
                }

                let random_chunk = random_block(data.to_vec(), samples);
                let stend = random_chunk.len();
                let dm = end >> 1;
                let sm = stend >> 1;
                let mut j = 0;
                let mut l = 1;
                aim(&data[..dm], &random_chunk[..sm], &mut j, &mut l);
                output.extend_from_slice(&data[..j]);

                let buff = &random_chunk[sm..];
                aim(buff, &data[j..], &mut j, &mut l);
                output.extend_from_slice(&buff[..j]);
                output.extend_from_slice(&data[l..]);
                return;
            }
            22..24 => {
                // Insert semirandom bytes
                if end < 2 {
                    continue;
                }

                let mut n = random(BUFSIZE);
                let position = random(end);
                for _ in 0..5 {
                    n = random(n);
                }

                if n == 0 {
                    n = 2;
                }
                output.extend_from_slice(&data[..position]);
                for _ in 0..n {
                    let r = random(data.len() - 2) + 2;
                    output.extend_from_slice(&[data[r - 1]]);
                }
                output.extend_from_slice(&data[position..]);
                return;
            }
            24 => {
                // Overwrite semirandom bytes
                if end < 2 {
                    continue;
                }

                let a = random(end - 2);
                let b = match rdrand() & 1 {
                    0 => random(core::cmp::min(BUFSIZE - 2, end - a - 2)) + a + 2,
                    _ => random(32) + a + 2,
                };

                output.extend_from_slice(&data[..a]);
                for _ in a..b {
                    let r = random(end - 1);

                    // Access to a single character in &[u8]
                    output.extend_from_slice(&[data[r]]);
                }

                // Possible b can be longer than data
                if end > b {
                    output.extend_from_slice(&data[b..]);
                }
                return;
            }
            25..29 => {
                if end < 2 {
                    continue;
                }

                let mut result = None;

                // Attempt to find a number at a random location in the data buffer
                for _ in 0..random(AIMROUNDS) {
                    if result.is_some() {
                        break;
                    }

                    result = seek_num(data);
                }

                match result {
                    Some((num_start, num_end)) => {
                        // Write the data before the number
                        output.extend_from_slice(&data[..num_start]);

                        // Try to parse the found number into a usize
                        if let Ok(num) = str::from_utf8(&data[num_start..num_end])
                            .unwrap()
                            .parse::<i64>()
                        {
                            // Write the twiddled number
                            let twiddled = if num == 0 { twiddle(0) } else { twiddle(num) };
                            // let raw_bytes: [u8; 8] = unsafe { std::mem::transmute(twiddled) };
                            output.extend_from_slice(&twiddled.to_le_bytes());
                        }

                        // Write the rest of the buffer
                        output.extend_from_slice(&data[num_end..]);
                    }
                    _ => {
                        // Did not find a number in the data buffer
                        // Continue to try a different mutation method
                        // println!("Did not find number");
                        continue;
                    }
                }

                return;
            }
            29..35 => {
                // delimited swap

                match drange(data) {
                    // If we didn't find a delimiter, try again for a different mutation strategy
                    None => continue,
                    Some((delim1_start, delim1_end)) => {
                        let delim = data[delim1_start..].iter().nth(0).unwrap();
                        match other_drange(data, *delim) {
                            None => continue,
                            Some((delim2_start, delim2_end)) => {
                                // Swap the two found delimited substrings
                                output.extend_from_slice(&data[..delim1_start]);
                                output.extend_from_slice(&data[delim2_start..delim2_end]);
                                if delim2_start > delim1_end {
                                    output.extend_from_slice(&data[delim1_end..delim2_start]);
                                }
                                output.extend_from_slice(&data[delim1_start..delim1_end]);
                                output.extend_from_slice(&data[delim2_end..]);
                            }
                        }
                    }
                }

                return;
            }
            _ => unimplemented!(),
        }
    }
}

// fn ni_area<W: Write>(data: &[u8], samples: &Vec<Vec<u8>>, n: usize, output: &mut W) {
fn ni_area(data: &[u8], samples: &Vec<Vec<u8>>, n: usize, output: &mut Vec<u8>) {
    let length = data.len();
    // println!("ni_area: data.len(): {} n: {}", length, n);
    if n == 0 {
        output.extend_from_slice(data);
    } else if n == 1 || length < 256 {
        mutate_area(data, samples, output);
    } else {
        let mut split = random(length);
        while split == 1 {
            split = random(length);
            // println!("Finding new split: {}", split);
        }

        // let new_n = random(n / 2);
        let new_n = random(n - random(n));

        /*
        println!(
            "ni_area: length: {} n: {} new_n: {} split: {}",
            length, n, new_n, split
        );
        */
        ni_area(&data[..split], samples, n - new_n, output);
        ni_area(&data[split..], samples, new_n, output);
    }
}

/// Mutate a corpus of samples for a given number of results
///
/// # Example
///
/// ```
/// let samples = vec![
///             "<test><SUPERINNER!/></test><h>",
///             "<test></test>",
///             "<bingo><yay></bingo>"
///             ];
///
/// let mutations = ni_rs::mutate_samples(samples, 32);
/// assert_eq!(mutations.len(), 32);
/// ```
pub fn mutate_samples_n(samples: &Vec<Vec<u8>>, rounds: usize) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    // println!("mutate_samples_n: samples.len(): {}", samples.len());

    for _ in 0..rounds {
        let mut output_sample = Vec::new();
        let curr_sample = &samples[random(samples.len())];
        // println!("mutate_sampels_n: curr_sample.len(): {}", curr_sample.len());
        let n = if rdrand() & 3 == 1 {
            1
        } else {
            2 + random(curr_sample.len() >> 12 + 8)
        };
        // println!("mutate_sampels_n: n: {}", n);
        ni_area(&curr_sample, &samples, n, &mut output_sample);
        result.push(output_sample);
    }

    result
}

/// Mutate a corpus of samples for a single result
///
/// # Example
///
/// ```
/// let samples = vec![
///             "<test><SUPERINNER!/></test><h>",
///             "<test></test>",
///             "<bingo><yay></bingo>"
///             ];
///
/// let mutation = ni_rs::mutate_samples(samples);
/// ```
pub fn mutate_samples(samples: &Vec<Vec<u8>>) -> Vec<u8> {
    mutate_samples_n(samples, 1)
        .iter()
        .next()
        .unwrap()
        .to_owned()
}

/// Mutate a single sample for a single result
///
/// # Example
///
/// ```
/// let data = "<test><SUPERINNER!/></test>";
/// let res = ni_rs::mutate(data);
/// ```
pub fn mutate(data: Vec<u8>) -> Vec<u8> {
    let samples = vec![data];
    mutate_samples_n(&samples, 1)
        .iter()
        .next()
        .unwrap()
        .to_owned()
}

/// Mutate a single sample for a given number of results
///
/// # Example
///
/// ```
/// let data = "<test><SUPERINNER!/></test>";
/// let mutations = ni_rs::mutate_n(data, 32);
/// assert_eq!(mutations.len(), 32);
/// ```
pub fn mutate_n(data: Vec<u8>, rounds: usize) -> Vec<Vec<u8>> {
    let samples = vec![data];
    mutate_samples_n(&samples, rounds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test1() {
        let mut output = Vec::new();
        let sample = "<test><SUPERINNER!/></test><h>";
        let samples = vec![sample];
        mutate_area(sample, &samples, &mut output);
        eprintln!(
            "before {} after {}",
            sample,
            str::from_utf8(&output).unwrap()
        );
        // assert_eq!(str::from_utf8(&output).unwrap(), "bbbb")
        assert!(false);
    }

    #[test]
    fn test2() {
        let samples = mutate_samples(
            vec![
                "<test><SUPERINNER!/></test><h>",
                "<test></test>",
                "<bingo><yay></bingo>",
            ],
            10,
        );
        assert_eq!(samples, vec!["test"]);
    }
}
