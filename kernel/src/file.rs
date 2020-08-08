//! Faking file operations 
use alloc::vec::Vec;
use alloc::string::String;

#[derive(Debug, Clone)]
pub struct File {
    /// Filename
    pub name: String,

    /// Opened with `r` mode
    pub read: bool,

    /// Opened with `w` mode
    pub write: bool,

    /// Is currently open
    pub open: bool,
    
    /// Current file position for reading
    pub position: usize,

    /// File backing bytes
    pub buffer: Vec<u8>,

    /// Number of people holding this file
    pub owners: usize
}

impl File {
    /// Open a file with the given mode and an empty file backing
    pub fn from_name(name: String, mode: String) -> File {
        let read = mode.contains("r") || mode.contains("R");
        let write = mode.contains("w") || mode.contains("W");

        assert!(!mode.contains("a") && !mode.contains("A"), "Append mode not implemented");
        assert!(!mode.contains("+"), "Update mode not implemented");
    
        File {
            name,
            read,
            write,
            open: true,
            position: 0,
            buffer: Vec::new(),
            owners: 1
        }
    }

    pub fn from_name_with_buffer(name: String, mode: String, buffer: Vec<u8>) -> File {
        let read = mode.contains("r") || mode.contains("R");
        let write = mode.contains("w") || mode.contains("W");

        assert!(!mode.contains("a") && !mode.contains("A"), "Append mode not implemented");
        assert!(!mode.contains("+"), "Update mode not implemented");

        File {
            name,
            read,
            write,
            open: true,
            position: 0,
            buffer,
            owners: 1
        }
    }

    pub fn set_buffer(&mut self, buffer: Vec<u8>) {
        self.buffer = buffer;
    }

    /// Read `count` bytes from the current file
    pub fn read(&mut self, count: usize) -> Vec<u8> {
        // Read and convert the wanted slice to a vec
        assert!(self.buffer.len() > 0, "Attempted to read file with no buffer");

        // Seek is way out of bounds of the data length, return junk data
        if self.position > self.buffer.len() {
            // print!("TOTALLY OOB\n");
            return vec![0xff; count];
        }

        // Start in the file, but eventually read OOB data. Return 0xee as the junk data.
        if self.position + count > self.buffer.len() {
            // print!("PARTIAL OOB\n");
            let mut result = self.buffer[self.position..].to_vec();
            result.extend(vec![0xff; count - result.len()]);
            return result;
        }

        let result = self.buffer[self.position..self.position + count].to_vec();
        self.position += count;
        result
    }

    /// Return the length of the buffer of this file backing
    pub fn len(&mut self) -> usize {
        self.buffer.len()
    }

    /// Alias for `ftell` to return the length of the buffer of this file backing
    pub fn tell(&mut self) -> usize {
        self.len()
    }

    /// Seek to a new location in the file
    ///
    /// From the `fseek` docs:
    ///  0 (SEEK_SET)	Beginning of file
    ///  1 (SEEK_CUR)	Current position of the file pointer
    ///  2 (SEEK_END)	End of file *
    pub fn seek(&mut self, offset: u64, origin: u64) {
        // Calculate the starting offset from the `origin` argument from `fseek`
        let starting_offset = match origin {
            0 => 0,
            1 => self.position,
            2 => {
                assert!((offset as i32) <= 0, "Received SEEK_END with positive offset");
                self.buffer.len()
            }
            _ => unimplemented!()
        };

        // Add the requested offset from the `fseek` 3rd paremter
        let new_position = starting_offset as i32 + offset as i32;

        // Update the position in the File
        // print!("New Pos: {}: {:#x} -> {:#x}\n", self.name, self.position, new_position);
        self.position = new_position as usize;
    }
}

#[derive(Debug)]
pub struct Files {
    pub files: Vec<File>,
    pub handle_offset: usize
}

impl Files {
    pub fn new() -> Files {
        Files { files: Vec::new(), handle_offset: 0xdead0000 }
    }

    /// Create a new file via name and buffer
    pub fn new_file(&mut self, name: String, mode: String) -> usize {
        if let Some(handle) = self.get_handle_by_name(&name) {
            if self.is_open(handle) {
                assert!(!mode.contains("w") && !mode.contains("W"), 
                    &format!("Attempted to open already opened read file: {}\n", name)
                );

                let index = handle - self.handle_offset;

                assert!(index < self.files.len());

                let curr_file = &mut self.files[index];
                curr_file.owners += 1;
                return handle;
            }

            self.set_open(handle, true);
            self.set_mode(handle, &mode);
            return handle;
        }
        
        // Must not have a `0` file handle since that is an error case
        let handle = self.handle_offset + self.files.len();

        // print!("New file: {} -> {:#x}\n", name, handle);

        // Creat and add the new file to the databse 
        let new_file = File::from_name(name, mode);
        self.files.push(new_file);
        handle
    }

    /// Create a new file via name and buffer
    pub fn new_file_with_buffer(&mut self, name: String, mode: String, buffer: Vec<u8>) -> usize {
        // Must not have a `0` file handle since that is an error case
        let handle = self.handle_offset + self.files.len();
        // print!("New file: {} -> {:#x}\n", name, handle);

        // Creat and add the new file to the databse 
        let new_file = File::from_name_with_buffer(name, mode, buffer);
        self.files.push(new_file);
        handle
    }

    fn get_handle_by_name(&self, name: &str) -> Option<usize> {
        for (i, file) in self.files.iter().enumerate() {
            if file.name == name {
                return Some(i + self.handle_offset);
            }
        }

        None
    }

    pub fn is_open(&self, handle: usize) -> bool {
        // Convert the handle to the index into the files vec
        let handle = handle - self.handle_offset;

        // Ensure the file handle is in our database (aka the index into the files Vec)
        assert!(handle < self.files.len());

        self.files[handle].open
    }

    pub fn set_open(&mut self, handle: usize, open: bool) {
        // Convert the handle to the index into the files vec
        let handle = handle - self.handle_offset;

        // Ensure the file handle is in our database (aka the index into the files Vec)
        assert!(handle < self.files.len());

        self.files[handle].open = open;
    }

    pub fn set_mode(&mut self, handle: usize, mode: &str) {
        // Convert the handle to the index into the files vec
        let handle = handle - self.handle_offset;

        // Ensure the file handle is in our database (aka the index into the files Vec)
        assert!(handle < self.files.len());

        self.files[handle].read  = mode.contains("r") || mode.contains("R");
        self.files[handle].write = mode.contains("w") || mode.contains("W");
    }

    pub fn set_buffer(&mut self, handle: usize, buffer: Vec<u8>) {
        // Convert the handle to the index into the files vec
        let handle = handle - self.handle_offset;

        // Ensure the file handle is in our database (aka the index into the files Vec)
        assert!(handle < self.files.len());

        // Set the buffer for this file
        let file = &mut self.files[handle];
        assert!(file.open, "Attempted to set buffer on closed file");
        file.set_buffer(buffer);
    }

    /// Clear the currently opened files
    pub fn clear(&mut self) {
        // print!("Clearing files\n");
        self.files = Vec::new();
        // print!("{:?}\n", self);
    }

    /// Read from one of the current opened files
    pub fn read(&mut self, handle: usize, size: usize) -> Vec<u8> {
        // print!("Read({:#x}, {:#x})\n", handle, size);

        // Convert the handle to the index into the files vec
        let handle = handle - self.handle_offset;

        // Ensure the file handle is in our database (aka the index into the files Vec)
        assert!(handle < self.files.len());

        // Read from the wanted file
        let file = &mut self.files[handle];
        assert!(file.open, "Attempted to read closed file!");
        file.read(size)
    }

    /// Seek in one of the currently opened files
    /// 
    /// From the `fseek` docs:
    ///  0 (SEEK_SET)	Beginning of file
    ///  1 (SEEK_CUR)	Current position of the file pointer
    ///  2 (SEEK_END)	End of file *
    pub fn seek(&mut self, handle: usize, offset: u64, origin: u64) {
        // print!("Seek({:#x}, {:#x}, {:#x})\n", handle, offset, origin);

        // Convert the handle to the index into the files vec
        let handle = handle - self.handle_offset;

        // Ensure the file handle is in our database (aka the index into the files Vec)
        assert!(handle < self.files.len());

        // Seek in the wanted file
        let file = &mut self.files[handle];
        assert!(file.open, "Attempted to read closed file!");
        file.seek(offset, origin);
    }

    pub fn close(&mut self, curr_handle: usize) {
        // Convert the handle to the index into the files vec
        let handle = curr_handle - self.handle_offset;

        // Ensure the file handle is in our database (aka the index into the files Vec)
        if handle >= self.files.len() {
            print!("Ignoring file handle that we don't know about: {:#x}\n", curr_handle);
            return;
        }

        // Attempt to close the open file
        let mut file = &mut self.files[handle];

        file.owners -= 1;

        if file.owners == 0 {
            assert!(file.open, "Attempted to close opened file!");
            file.open = false;
        }
    }

    pub fn tell(&mut self, curr_handle: usize) -> usize {
        // Convert the handle to the index into the files vec
        let handle = curr_handle - self.handle_offset;

        // Ensure the file handle is in our database (aka the index into the files Vec)
        assert!(handle < self.files.len());

        self.files[handle].position
    }

    pub fn buffer_len(&self, curr_handle: usize) -> usize {
        // Convert the handle to the index into the files vec
        let handle = curr_handle - self.handle_offset;

        // Ensure the file handle is in our database (aka the index into the files Vec)
        assert!(handle < self.files.len());

        self.files[handle].buffer.len()
    }
    
    /// Return the position of the given handle
    pub fn getpos(&self, curr_handle: usize) -> usize {
        // Convert the handle to the index into the files vec
        let handle = curr_handle - self.handle_offset;

        // Ensure the file handle is in our database (aka the index into the files Vec)
        assert!(handle < self.files.len());

        self.files[handle].position
    }
}
